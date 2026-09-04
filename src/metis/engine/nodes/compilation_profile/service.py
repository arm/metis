# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ast
import hashlib
import os
import re
import subprocess
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from metis.engine.source import ProfiledSourceArtifact
from metis.engine.source import ProfiledSourceReference
from metis.plugins.c_family.runtime import _mask_c_comments_and_literals

from .database import CompilationDatabase
from .database import CompilationUnit

_LINE_MARKER = re.compile(rb'^\s*#\s+(\d+)\s+"((?:\\.|[^"\\])*)"((?:\s+\d+)*)\s*$')
_SOURCE_LINE_DIRECTIVE = re.compile(
    rb"(?m)^[\t\v\f ]*(?:#|%:|\?\?=)[\t\v\f ]*"
    rb"(?:line\b|[0-9]+(?:[\t\v\f ]|$))"
)
_BLANK_LINE = bytes(13 if value == 13 else 32 for value in range(256))
_DROP_FLAGS = frozenset(
    {
        "-c",
        "-S",
        "-E",
        "-M",
        "-MM",
        "-MD",
        "-MMD",
        "-MG",
        "-MP",
        "-P",
        "--dependencies",
        "--user-dependencies",
        "--write-dependencies",
        "--write-user-dependencies",
        "--print-missing-file-dependencies",
        "--no-line-commands",
        "-dD",
        "-dI",
        "-dM",
        "-dN",
        "-fdirectives-only",
        "-fsyntax-only",
        "-frewrite-includes",
        "-save-stats",
        "-save-temps",
        "--save-temps",
    }
)
_DROP_WITH_VALUE = frozenset(
    {
        "-o",
        "--output",
        "-MF",
        "-MT",
        "-MQ",
        "-MJ",
        "-dependency-file",
        "-serialize-diagnostics",
        "--serialize-diagnostics",
        "--dump",
    }
)
_DROP_ATTACHED = (
    "-o",
    "-MF",
    "-MT",
    "-MQ",
    "-MJ",
    "--output=",
    "-dependency-file=",
    "-serialize-diagnostics=",
    "--serialize-diagnostics=",
    "-save-stats=",
    "-fdeps-file=",
    "-fdeps-format=",
    "-fdeps-target=",
    "--dump=",
)
_KEEP_WITH_VALUE = frozenset(
    {
        "-D",
        "-U",
        "-A",
        "-I",
        "-F",
        "-B",
        "-x",
        "-include",
        "-imacros",
        "-iquote",
        "-isystem",
        "-idirafter",
        "-iprefix",
        "-iwithprefix",
        "-iwithprefixbefore",
        "-isysroot",
        "-imultilib",
        "-imultiarch",
        "-iframework",
        "-iframeworkwithsysroot",
        "-target",
        "--target",
        "-arch",
        "--sysroot",
        "-resource-dir",
        "--gcc-toolchain",
        "-Xassembler",
        "-Xlinker",
        "--define-macro",
        "--undefine-macro",
        "--include",
        "--imacros",
        "--include-directory",
        "--include-directory-after",
        "--include-prefix",
        "--include-with-prefix",
        "--include-with-prefix-after",
        "--include-with-prefix-before",
    }
)
_UNSUPPORTED_PREFIXES = (
    "-fpch-preprocess",
    "-save-temps=",
    "--save-temps=",
    "-ftime-trace",
    "-fmodule-output",
    "-fmodules",
    "-fplugin",
    "-plugin",
    "-Xclang",
    "-Xpreprocessor",
)


@dataclass(frozen=True, slots=True)
class _ProfiledUnit:
    profile_id: str
    seen_files: frozenset[str]
    active_lines: Mapping[str, frozenset[int]]
    directive_sources: frozenset[Path]


def build_profiled_source(
    *,
    codebase_path: str,
    database: CompilationDatabase,
    timeout_seconds: int,
    jobs,
    progress_callback=None,
) -> ProfiledSourceArtifact:
    root = Path(codebase_path).expanduser().resolve()
    _validate_source_paths({unit.source for unit in database.units}, root)

    def preprocess(entry: CompilationUnit) -> _ProfiledUnit:
        return _preprocess(entry, root=root, timeout_seconds=timeout_seconds)

    units = jobs.run(
        database.units,
        preprocess,
        label=None,
        result_key=lambda entry: entry.profile_id,
        on_complete=(
            (
                lambda entry, completed, total: progress_callback(
                    {
                        "event": "compilation_profile_progress",
                        "completed": completed,
                        "total": total,
                        "file": _display_path(entry.source, root),
                    }
                )
            )
            if progress_callback is not None
            else None
        ),
    )
    views: dict[str, dict[str, frozenset[int]]] = defaultdict(dict)
    _validate_source_paths(
        {path for unit in units for path in unit.directive_sources},
        root,
    )
    raw_by_file = _read_sources(
        root,
        {path for unit in units for path in unit.seen_files},
    )
    for unit in units:
        for path in unit.seen_files:
            views[path][unit.profile_id] = unit.active_lines.get(path, frozenset())

    sources: dict[str, bytes] = {}
    active_line_count = 0
    for path, profiles in sorted(views.items()):
        source = raw_by_file[path]
        distinct = {
            frozenset(_include_line_continuations(source, active))
            for active in set(profiles.values())
        }
        if len(distinct) != 1:
            continue
        active = set(next(iter(distinct)))
        sources[path] = _mask_inactive_lines(source, active)
        active_line_count += len(active)
    if not views:
        raise ValueError(
            "Compilation database preprocessing produced no source under the codebase"
        )
    reference = ProfiledSourceReference(
        fingerprint=_fingerprint(raw_by_file, sources),
        compile_commands_path=_display_path(database.path, root),
        compile_commands_sha256=database.sha256,
        translation_units=len(database.units),
        source_views=sum(len(profile) for profile in views.values()),
        profiled_files=len(sources),
        ambiguous_files=len(views) - len(sources),
        active_line_count=active_line_count,
        compiler_names=tuple(
            sorted({Path(unit.argv[0]).name for unit in database.units})
        ),
    )
    return ProfiledSourceArtifact(
        reference=reference,
        languages=frozenset({"c", "cpp"}),
        raw_sources=raw_by_file,
        canonical_sources=sources,
    )


def _sanitized_argv(unit: CompilationUnit) -> tuple[str, ...]:
    filtered = [unit.argv[0]]
    source_present = False
    arguments = iter(unit.argv[1:])
    for argument in arguments:
        if argument in _KEEP_WITH_VALUE or argument in _DROP_WITH_VALUE:
            value = next(arguments, None)
            if value is None:
                raise ValueError(f"Compiler option {argument!r} requires a value")
            if value.startswith("@"):
                raise ValueError(
                    f"Compilation unit uses unsupported argument {value!r}"
                )
            if argument in _KEEP_WITH_VALUE:
                filtered.extend((argument, value))
            continue
        if (
            argument == "--"
            or argument.startswith("@")
            or argument.startswith(_UNSUPPORTED_PREFIXES)
        ):
            raise ValueError(f"Compilation unit uses unsupported argument {argument!r}")
        if argument.startswith("-Wp,"):
            parts = argument.split(",")
            if len(parts) == 3 and parts[1] in {"-MD", "-MMD"} and parts[2]:
                continue
            raise ValueError(
                f"Compilation unit uses unsupported argument group {argument!r}; "
                "use separate compiler flags for macros, includes, and dependencies"
            )
        if argument in _DROP_FLAGS or argument.startswith(_DROP_ATTACHED):
            continue
        filtered.append(argument)
        if not argument.startswith("-"):
            candidate = Path(argument)
            candidate = (
                candidate if candidate.is_absolute() else unit.directory / candidate
            )
            try:
                source_present = source_present or candidate.resolve() == unit.source
            except OSError:
                pass
    if not source_present:
        filtered.append(str(unit.source))
    return tuple(filtered)


def _preprocess(
    unit: CompilationUnit,
    *,
    root: Path,
    timeout_seconds: int,
) -> _ProfiledUnit:
    argv = (*_sanitized_argv(unit), "-E", "-fdirectives-only", "-o", "-")
    try:
        completed = subprocess.run(
            argv,
            cwd=unit.directory,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"Preprocessing failed for {_display_path(unit.source, root)}: "
            f"{type(exc).__name__}"
        ) from exc
    if completed.returncode:
        detail = completed.stderr[:4096].decode("utf-8", errors="replace").strip()
        if len(completed.stderr) > 4096:
            detail += "\n[compiler diagnostics truncated]"
        raise RuntimeError(
            f"Preprocessing failed for {_display_path(unit.source, root)} "
            f"with exit code {completed.returncode}"
            + (f":\n{detail}" if detail else "")
        )
    seen, lines, directive_sources = _mapped_lines(
        completed.stdout,
        directory=unit.directory,
        root=root,
        source=unit.source,
    )
    if not seen:
        raise RuntimeError(
            f"Preprocessing produced no source markers for "
            f"{_display_path(unit.source, root)}"
        )
    return _ProfiledUnit(
        unit.profile_id,
        frozenset(seen),
        {path: frozenset(active) for path, active in lines.items()},
        frozenset(directive_sources),
    )


def _mapped_lines(
    output: bytes,
    *,
    directory: Path,
    root: Path,
    source: Path,
) -> tuple[set[str], dict[str, set[int]], set[Path]]:
    seen: set[str] = set()
    mapped: dict[str, set[int]] = defaultdict(set)
    directive_sources: set[Path] = set()
    current_path: str | None = None
    current_line = 0
    physical_path: Path | None = source.resolve()
    for line in output.splitlines():
        marker = _LINE_MARKER.match(line)
        if marker is not None:
            current_line = int(marker.group(1))
            flags = {int(value) for value in marker.group(3).split()}
            marker_file, marker_path = _marker_paths(
                marker.group(2), directory=directory, root=root
            )
            if physical_path is not None and marker_file != physical_path:
                directive_sources.add(physical_path)
            if flags & {1, 2} and marker_file is not None:
                physical_path = marker_file
            current_path = marker_path
            if current_path is not None:
                seen.add(current_path)
            continue
        if current_path is not None and line.strip():
            mapped[current_path].add(current_line)
        current_line += 1
    return seen, mapped, directive_sources


def _marker_paths(
    raw: bytes,
    *,
    directory: Path,
    root: Path,
) -> tuple[Path | None, str | None]:
    try:
        literal = "".join(
            chr(value) if value < 128 else f"\\x{value:02x}" for value in raw
        )
        decoded = ast.literal_eval(f'b"{literal}"')
        value = os.fsdecode(decoded)
    except (SyntaxError, ValueError):
        return None, None
    if value.startswith("<") or value.endswith("//"):
        return None, None
    candidate = Path(value)
    candidate = candidate if candidate.is_absolute() else directory / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        return None, None
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError:
        relative = None
    return resolved, relative


def _read_sources(root: Path, paths: set[str]) -> dict[str, bytes]:
    try:
        sources = {path: (root / path).read_bytes() for path in paths}
    except OSError as exc:
        raise RuntimeError("Unable to snapshot profiled source") from exc
    _validate_sources(sources)
    return sources


def _validate_source_paths(paths: set[Path], root: Path) -> None:
    try:
        sources = {_display_path(path, root): path.read_bytes() for path in paths}
    except OSError as exc:
        raise RuntimeError("Unable to verify included source") from exc
    _validate_sources(sources)


def _validate_sources(sources: Mapping[str, bytes]) -> None:
    for path, source in sources.items():
        if b"\r" in source.replace(b"\r\n", b""):
            raise RuntimeError(
                f"Compilation profiles require LF or CRLF line endings: {path}"
            )
        logical = re.sub(rb"\\\r?\n", b"", source.replace(b"??/", b"\\"))
        if _SOURCE_LINE_DIRECTIVE.search(_mask_c_comments_and_literals(logical)):
            raise RuntimeError(
                f"Compilation profiles do not support source #line directives: {path}"
            )


def _mask_inactive_lines(source: bytes, active_lines: set[int]) -> bytes:
    return b"\n".join(
        line if line_number in active_lines else line.translate(_BLANK_LINE)
        for line_number, line in enumerate(source.split(b"\n"), 1)
    )


def _include_line_continuations(
    source: bytes, active: Mapping | set | frozenset
) -> set[int]:
    lines = source.splitlines()
    expanded = set(active)
    for line_number in active:
        current = line_number
        while 1 <= current <= len(lines) and lines[current - 1].rstrip(
            b" \t\r"
        ).endswith(b"\\"):
            current += 1
            if current <= len(lines):
                expanded.add(current)
    return expanded


def _fingerprint(
    raw_sources: Mapping[str, bytes],
    sources: Mapping[str, bytes],
) -> str:
    digest = hashlib.sha256(b"metis-compilation-profile-v2\0")
    for path in sorted(raw_sources):
        for value in (
            os.fsencode(path),
            raw_sources[path],
            b"\1" + sources[path] if path in sources else b"\0",
        ):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)
    return digest.hexdigest()


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return str(path)
