# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from itertools import islice
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
from tempfile import NamedTemporaryFile
from threading import Lock
from time import monotonic
from typing import Sequence

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from metis.engine.source import SourceMap
from metis.generated_artifacts import generated_artifact_paths
from metis.utils import resolve_path_within_root, source_lines

_PYTHON_REGEX_REWRITES = (
    ("[[:space:]]", r"\s"),
    ("[[:blank:]]", r"[ \t]"),
)
_NATIVE_GREP_OPTIONS = (
    "-HrEn",
    "--exclude-dir=.[mM][eE][tT][iI][sS]",
    "--exclude=.[mM][eE][tT][iI][sS]",
)


class NavigationCapabilityConfiguration(BaseModel):
    timeout_seconds: int = Field(gt=0)
    max_chars: int = Field(gt=0)

    model_config = ConfigDict(extra="forbid", frozen=True)


class NavigationCapability:
    def __init__(
        self,
        *,
        codebase_path: str,
        timeout_seconds: int,
        max_chars: int,
    ):
        self.codebase_path = Path(codebase_path).resolve()
        self.timeout_seconds = timeout_seconds
        self.max_chars = max_chars
        # Serialize subprocess tools; add a measured FD-aware pool if tool
        # latency becomes material.
        self._subprocess_lock = Lock()
        self._has_grep = self._supports_native_tool(
            ["grep", *_NATIVE_GREP_OPTIONS, "--", "", os.devnull],
            ok_returncodes=(1,),
        )
        self._has_find = self._supports_native_tool(
            [
                *self._find_files(
                    str(self.codebase_path), frozenset({self.codebase_path})
                ),
                "-print0",
                "-exec",
                sys.executable,
                "{}",
                "+",
            ]
        )

    def _supports_native_tool(
        self, argv: Sequence[str], *, ok_returncodes: tuple[int, ...] = (0,)
    ) -> bool:
        if shutil.which(argv[0]) is None:
            return False
        try:
            self._run(argv, ok_returncodes=ok_returncodes)
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            return False
        return True

    def _resolve_path(
        self, raw_path: str, artifacts: frozenset[Path] | None = None
    ) -> Path:
        path = resolve_path_within_root(
            self.codebase_path, raw_path, preserve_aliases=True
        ).resolve()
        state_path = (self.codebase_path / ".metis").resolve()
        state_identity = self._file_identity(state_path)
        if (
            path.is_relative_to(state_path)
            or any(
                part.casefold() == ".metis"
                for part in path.relative_to(self.codebase_path).parts
            )
            or (
                state_identity is not None
                and any(
                    self._file_identity(parent) == state_identity
                    for parent in (path, *path.parents)
                )
            )
        ):
            raise ValueError("Metis state is not source evidence")
        artifacts = (
            artifacts
            if artifacts is not None
            else generated_artifact_paths(
                self.codebase_path, timeout_seconds=self.timeout_seconds
            )
        )
        artifact_identities = {
            identity
            for artifact in artifacts
            if (identity := self._file_identity(artifact)) is not None
        }
        if path in artifacts or self._file_identity(path) in artifact_identities:
            raise ValueError("Generated Metis artifacts are not source evidence")
        return path

    @staticmethod
    def _file_identity(path: Path) -> tuple[int, int] | None:
        try:
            metadata = path.stat()
        except OSError:
            return None
        return metadata.st_dev, metadata.st_ino

    def _run(
        self,
        argv: Sequence[str],
        *,
        ok_returncodes: tuple[int, ...] = (0,),
        deadline: float | None = None,
        nul_records: bool = False,
    ) -> str:
        deadline = (
            deadline if deadline is not None else monotonic() + self.timeout_seconds
        )
        if not self._subprocess_lock.acquire(timeout=max(0, deadline - monotonic())):
            raise subprocess.TimeoutExpired(list(argv), self.timeout_seconds)
        try:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(list(argv), self.timeout_seconds)
            with subprocess.Popen(
                list(argv),
                cwd=str(self.codebase_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=not nul_records,
                start_new_session=os.name == "posix",
            ) as proc:
                try:
                    stdout, stderr = proc.communicate(
                        timeout=max(0, deadline - monotonic())
                    )
                except BaseException:
                    try:
                        if os.name == "posix":
                            os.killpg(proc.pid, signal.SIGKILL)
                        else:
                            proc.kill()
                    except ProcessLookupError:
                        pass
                    proc.communicate()
                    raise
        finally:
            self._subprocess_lock.release()
        if nul_records:
            stdout, stderr = os.fsdecode(stdout), os.fsdecode(stderr)
        stdout = (stdout or "") if nul_records else (stdout or "").strip()
        stderr = (stderr or "").strip()
        if proc.returncode not in ok_returncodes or stderr:
            detail = stderr or stdout or f"exit status {proc.returncode}"
            raise RuntimeError(f"{' '.join(argv)} failed: {detail}")
        if nul_records:
            return stdout[: self.max_chars].rpartition("\0")[0]
        return self._clip(stdout)

    def _clip(self, text: str) -> str:
        if len(text) > self.max_chars:
            return text[: self.max_chars] + "\n...[truncated]"
        return text

    def _iter_files(self, base: Path):
        def handle_discovery_error(error: OSError) -> None:
            raise error

        artifacts = generated_artifact_paths(
            self.codebase_path, timeout_seconds=self.timeout_seconds
        )
        state_path = (self.codebase_path / ".metis").resolve()
        state_identity = self._file_identity(state_path)
        excluded_identities = {
            identity
            for excluded in (*artifacts, state_path)
            if (identity := self._file_identity(excluded)) is not None
        }
        if (
            base.is_relative_to(state_path)
            or self._file_identity(base) in excluded_identities
            or (
                state_identity is not None
                and any(
                    self._file_identity(parent) == state_identity
                    for parent in base.parents
                )
            )
        ):
            return
        if base.is_file():
            yield base
            return
        for root, directories, files in os.walk(base, onerror=handle_discovery_error):
            root_path = Path(root)
            directories[:] = [
                name
                for name in directories
                if name.casefold() != ".metis"
                and self._file_identity(root_path / name) not in excluded_identities
            ]
            directories.sort(key=lambda name: (name.lower(), name))
            for name in sorted(files, key=lambda name: (name.lower(), name)):
                candidate = root_path / name
                if (
                    name.casefold() != ".metis"
                    and self._file_identity(candidate) not in excluded_identities
                    and not candidate.is_symlink()
                    and candidate.is_file()
                ):
                    yield candidate

    def grep(self, pattern: str, path: str) -> str:
        deadline = monotonic() + self.timeout_seconds
        artifacts = generated_artifact_paths(
            self.codebase_path, timeout_seconds=max(0, deadline - monotonic())
        )
        target = self._resolve_path(path, artifacts)
        relocated_state = (self.codebase_path / ".metis").is_symlink()
        needs_pruning = relocated_state or bool(artifacts)
        if self._has_grep and (not needs_pruning or self._has_find):
            relative_path = target.relative_to(self.codebase_path).as_posix()
            if relative_path.startswith("-") or relative_path in {"(", "!"}:
                relative_path = f"./{relative_path}"
            if needs_pruning and target.is_dir():
                with NamedTemporaryFile(
                    mode="w", encoding="utf-8", prefix="metis-grep-"
                ) as patterns:
                    patterns.write(pattern + "\n")
                    patterns.flush()
                    return self._run(
                        [
                            *self._find_files(relative_path, artifacts),
                            "-exec",
                            "grep",
                            "-HnE",
                            "-f",
                            patterns.name,
                            "--",
                            "{}",
                            "+",
                        ],
                        ok_returncodes=(0, 1),
                        deadline=deadline,
                    )
            return self._run(
                [
                    "grep",
                    *_NATIVE_GREP_OPTIONS,
                    "--",
                    pattern,
                    relative_path,
                ],
                ok_returncodes=(0, 1),
                deadline=deadline,
            )

        self._compile_pattern(pattern)
        return self._run_python_search("grep", pattern, target, deadline)

    def _find_files(self, relative_path: str, artifacts: frozenset[Path]) -> list[str]:
        argv = ["find", relative_path, "(", "-iname", ".metis"]
        state_path = (self.codebase_path / ".metis").resolve()
        for excluded in sorted({state_path, *artifacts}):
            if (
                not excluded.is_relative_to(self.codebase_path)
                or self._file_identity(excluded) is None
            ):
                continue
            argv.extend(["-o", "-samefile", str(excluded)])
        return [*argv, ")", "-prune", "-o", "-type", "f"]

    def _run_python_search(
        self, operation: str, value: str, target: Path, deadline: float
    ) -> str:
        return self._run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                str(self.codebase_path),
                str(self.timeout_seconds),
                str(self.max_chars),
                operation,
                value,
                str(target),
            ],
            deadline=deadline,
            nul_records=operation == "find",
        )

    @staticmethod
    def _compile_pattern(pattern: str) -> re.Pattern[str]:
        try:
            translated = pattern
            for source, replacement in _PYTHON_REGEX_REWRITES:
                translated = translated.replace(source, replacement)
            return re.compile(translated)
        except re.error as exc:
            raise ValueError(f"Invalid grep pattern: {exc}") from exc

    def _grep_python(self, pattern: str, target: Path) -> str:
        regex = self._compile_pattern(pattern)
        lines: list[str] = []
        for file_path in self._iter_files(target):
            rel = file_path.relative_to(self.codebase_path).as_posix()
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            for lineno, line in enumerate(source_lines(text), start=1):
                if regex.search(line):
                    lines.append(f"{rel}:{lineno}:{line}")
                    if sum(len(x) + 1 for x in lines) >= self.max_chars:
                        return self._clip("\n".join(lines))
        return self._clip("\n".join(lines))

    def find_name(self, name: str, max_results: int = 20) -> list[str]:
        deadline = monotonic() + self.timeout_seconds
        if not name or "/" in name or "\\" in name:
            return []
        if self._has_find:
            artifacts = generated_artifact_paths(
                self.codebase_path, timeout_seconds=max(0, deadline - monotonic())
            )
            output = self._run(
                [
                    *self._find_files(".", artifacts),
                    "-name",
                    re.sub(r"([\\*?\[])", r"\\\1", name),
                    "-print0",
                ],
                deadline=deadline,
                nul_records=True,
            )
        else:
            output = self._run_python_search("find", name, self.codebase_path, deadline)
        found: list[str] = []
        for item in (output or "").split("\0"):
            if not item:
                continue
            if item.startswith("./"):
                item = item[2:]
            found.append(item)
        results: list[str] = []
        for item in sorted(set(found), key=lambda path: (path.lower(), path)):
            results.append(item)
            if len(results) >= max_results:
                break
        return results

    def cat(self, path: str) -> str:
        target = self._resolve_path(path)
        if not target.is_file():
            raise FileNotFoundError(str(target))
        text = target.read_text(encoding="utf-8", errors="ignore")
        return self._clip(SourceMap.number_text(text, 1))

    def sed(self, path: str, start_line: int, end_line: int) -> str:
        if end_line < start_line:
            raise ValueError("end_line must be >= start_line")
        target = self._resolve_path(path)
        if not target.is_file():
            raise FileNotFoundError(str(target))
        start_idx = max(0, start_line - 1)
        with target.open(encoding="utf-8", errors="ignore") as source:
            if end_line < 0:
                lines = source.readlines()[:end_line]
            else:
                lines = islice(
                    source, min(start_idx, sys.maxsize), min(end_line, sys.maxsize)
                )
            body = "".join(lines)
        return self._clip(SourceMap.number_text(body, start_idx + 1))


if __name__ == "__main__":
    navigation = NavigationCapability(
        codebase_path=sys.argv[1],
        timeout_seconds=int(sys.argv[2]),
        max_chars=int(sys.argv[3]),
    )
    if sys.argv[4] == "grep":
        output = navigation._grep_python(sys.argv[5], Path(sys.argv[6]))
    else:
        output = "".join(
            path.relative_to(navigation.codebase_path).as_posix() + "\0"
            for path in navigation._iter_files(navigation.codebase_path)
            if path.name == sys.argv[5]
        )
    sys.stdout.buffer.write(os.fsencode(output))
