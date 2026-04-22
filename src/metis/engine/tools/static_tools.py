# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import subprocess
from typing import Sequence


_PYTHON_REGEX_REWRITES = (
    ("[[:space:]]", r"\s"),
    ("[[:blank:]]", r"[ \t]"),
)
_SHELL_REGEX_REWRITES = (
    (r"\s", "[[:space:]]"),
    (r"\S", "[^[:space:]]"),
    (r"\d", "[[:digit:]]"),
    (r"\D", "[^[:digit:]]"),
    (r"\w", "[[:alnum:]_]"),
    (r"\W", "[^[:alnum:]_]"),
    ("(?:", "("),
    (r"\A", "^"),
    (r"\Z", "$"),
)
_RISKY_SHELL_GREP_PATTERNS = (
    re.compile(r"\\[1-9]"),
    re.compile(r"\\[bB]"),
    re.compile(r"\\[pPkKQEGg]"),
    re.compile(r"\(\?(?!i\))"),
    re.compile(r"(\*\?|\+\?|\?\?|\*\+|\+\+|\?\+)"),
    re.compile(r"\{\d+(,\d*)?\}[?+]"),
)


class StaticToolRunner:
    def __init__(
        self,
        *,
        codebase_path: str,
        workspace_root: str | None = None,
        timeout_seconds: int = 8,
        max_chars: int = 16000,
    ):
        self.codebase_path = Path(codebase_path).resolve()
        self.workspace_root = self._resolve_workspace_root(workspace_root)
        self.search_root = self.workspace_root
        self.timeout_seconds = timeout_seconds
        self.max_chars = max_chars
        self._has_grep = shutil.which("grep") is not None
        self._has_find = shutil.which("find") is not None
        self._has_cat = shutil.which("cat") is not None
        self._has_sed = shutil.which("sed") is not None

    def _resolve_workspace_root(self, workspace_root: str | None) -> Path:
        if workspace_root:
            root = Path(workspace_root).resolve()
            if root == self.codebase_path or root in self.codebase_path.parents:
                return root
            return self.codebase_path

        for candidate in (self.codebase_path, *self.codebase_path.parents):
            git_dir = candidate / ".git"
            if git_dir.exists():
                return candidate
        return self.codebase_path

    def describe_tool(self, name: str) -> dict[str, str]:
        if name == "grep":
            backend = "shell_grep" if self._has_grep else "python_regex"
            return {"backend": backend}
        if name == "find_name":
            backend = "shell_find" if self._has_find else "python_walk"
            return {"backend": backend}
        if name == "cat":
            backend = "shell_cat" if self._has_cat else "python_read"
            return {"backend": backend}
        if name == "sed":
            backend = "shell_sed" if self._has_sed else "python_slice"
            return {"backend": backend}
        return {}

    def describe_call(self, name: str, *args, **kwargs) -> dict[str, str]:
        if name != "grep":
            return self.describe_tool(name)
        pattern = ""
        if args:
            pattern = str(args[0] or "")
        elif "pattern" in kwargs:
            pattern = str(kwargs.get("pattern") or "")
        backend = self._grep_backend(pattern)
        return {"backend": backend}

    def _resolve_path(self, raw_path: str) -> Path:
        fallback = None
        for candidate_raw in self._normalize_tool_path_candidates(raw_path):
            for base_root in self._candidate_base_roots(candidate_raw):
                if os.path.isabs(candidate_raw):
                    candidate = Path(candidate_raw).resolve()
                else:
                    candidate = (base_root / candidate_raw).resolve()
                if not self._is_within_allowed_roots(candidate):
                    continue
                if fallback is None:
                    fallback = candidate
                if candidate.exists():
                    return candidate
        if fallback is None:
            raise ValueError("Path escapes codebase")
        return fallback

    def _candidate_base_roots(self, candidate_raw: str) -> list[Path]:
        if os.path.isabs(candidate_raw):
            return [Path("/")]
        ordered: list[Path] = []
        for root in (self.codebase_path, self.workspace_root):
            if root in ordered:
                continue
            ordered.append(root)
        return ordered

    def _is_within_allowed_roots(self, candidate: Path) -> bool:
        for root in {self.codebase_path, self.workspace_root}:
            if candidate == root or root in candidate.parents:
                return True
        return False

    def _display_root(self) -> Path:
        return self.workspace_root

    def _normalize_tool_path_candidates(self, raw_path: str) -> list[str]:
        raw = str(raw_path or "").strip()
        if not raw:
            return [raw]
        if os.path.isabs(raw):
            return [raw]

        normalized = raw.replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        normalized = normalized or "."

        candidates: list[str] = []
        seen: set[str] = set()

        def add(candidate: str) -> None:
            text = str(candidate or "").strip() or "."
            if text in seen:
                return
            seen.add(text)
            candidates.append(text)

        add(normalized)

        raw_parts = PurePosixPath(normalized).parts
        codebase_parts = tuple(
            part
            for part in PurePosixPath(self.codebase_path.as_posix()).parts
            if part != "/"
        )
        suffixes = sorted(
            (
                codebase_parts[idx:]
                for idx in range(len(codebase_parts))
                if codebase_parts[idx:]
            ),
            key=len,
            reverse=True,
        )
        for suffix in suffixes:
            if len(suffix) > len(raw_parts):
                continue
            if raw_parts[: len(suffix)] != suffix:
                continue
            remainder = raw_parts[len(suffix) :]
            add(PurePosixPath(*remainder).as_posix() if remainder else ".")

        tail_candidates = [
            codebase_parts[idx:]
            for idx in range(len(codebase_parts))
            if codebase_parts[idx:]
        ]
        for tail in tail_candidates:
            if len(raw_parts) > len(tail):
                continue
            if tail[: len(raw_parts)] != raw_parts:
                continue
            add(".")

        return candidates

    def _run(
        self,
        argv: Sequence[str],
        *,
        ok_returncodes: tuple[int, ...] = (0,),
    ) -> str:
        proc = subprocess.run(
            list(argv),
            cwd=str(self.codebase_path),
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
        )
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        if proc.returncode not in ok_returncodes:
            detail = stderr or stdout or f"exit status {proc.returncode}"
            raise RuntimeError(f"{' '.join(argv)} failed: {detail}")
        return self._clip(stdout)

    def _clip(self, text: str) -> str:
        if len(text) > self.max_chars:
            return text[: self.max_chars] + "\n...[truncated]"
        return text

    def _grep_backend(self, pattern: str) -> str:
        if not self._has_grep:
            return "python_regex"
        if self._is_risky_shell_grep_pattern(pattern):
            return "python_regex"
        return "shell_grep"

    def _is_risky_shell_grep_pattern(self, pattern: str) -> bool:
        text = str(pattern or "")
        for compiled in _RISKY_SHELL_GREP_PATTERNS:
            if compiled.search(text):
                return True
        return False

    def _normalize_shell_grep_pattern(self, pattern: str) -> tuple[str, bool]:
        normalized = str(pattern or "")
        ignore_case = False
        if normalized.startswith("(?i)"):
            ignore_case = True
            normalized = normalized[4:]
        for source, replacement in _SHELL_REGEX_REWRITES:
            normalized = normalized.replace(source, replacement)
        return normalized, ignore_case

    def _compile_python_regex(self, pattern: str) -> re.Pattern[str]:
        normalized, ignore_case = self._normalize_shell_grep_pattern(pattern)
        translated = normalized
        for source, replacement in _PYTHON_REGEX_REWRITES:
            translated = translated.replace(source, replacement)
        flags = re.IGNORECASE if ignore_case else 0
        return re.compile(translated, flags)

    def _prepare_grep_call(
        self, pattern: str
    ) -> tuple[str, list[str] | re.Pattern[str]]:
        backend = self._grep_backend(pattern)
        if backend == "shell_grep":
            normalized, ignore_case = self._normalize_shell_grep_pattern(pattern)
            argv = ["grep"]
            if ignore_case:
                argv.append("-i")
            argv.extend(["-HREn", "--", normalized])
            return backend, argv
        try:
            compiled = self._compile_python_regex(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid grep pattern: {exc}") from exc
        return backend, compiled

    def _iter_files(self, base: Path):
        if base.is_file():
            yield base
            return
        if not base.exists():
            return
        for root, _, files in os.walk(base):
            root_path = Path(root)
            for name in files:
                yield root_path / name

    def grep(self, pattern: str, path: str) -> str:
        target = self._resolve_path(path)
        backend, prepared = self._prepare_grep_call(pattern)
        if backend == "shell_grep":
            return self._run(
                [*prepared, str(target)],
                ok_returncodes=(0, 1),
            )

        regex = prepared

        lines: list[str] = []
        for file_path in self._iter_files(target):
            rel = file_path.relative_to(self._display_root()).as_posix()
            try:
                text = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    lines.append(f"{rel}:{lineno}:{line}")
                    if sum(len(x) + 1 for x in lines) >= self.max_chars:
                        return self._clip("\n".join(lines))
        return self._clip("\n".join(lines))

    def find_name(self, name: str, max_results: int = 20) -> list[str]:
        if not name or "/" in name or "\\" in name:
            return []
        if self._has_find:
            output = self._run(
                ["find", str(self.search_root), "-type", "f", "-name", name]
            )
            found: list[str] = []
            for line in (output or "").splitlines():
                item = line.strip()
                if not item or item.startswith("find:"):
                    continue
                candidate = Path(item)
                try:
                    rel = (
                        candidate.resolve().relative_to(self._display_root()).as_posix()
                    )
                except Exception:
                    rel = item[2:] if item.startswith("./") else item
                found.append(rel.replace("\\", "/"))
        else:
            found = []
            for file_path in self._iter_files(self.search_root):
                if file_path.name != name:
                    continue
                try:
                    item = file_path.relative_to(self._display_root()).as_posix()
                except Exception:
                    continue
                found.append(item)
        results: list[str] = []
        for item in sorted(set(found), key=lambda p: p.lower()):
            results.append(item)
            if len(results) >= max_results:
                break
        return results

    def cat(self, path: str) -> str:
        target = self._resolve_path(path)
        if self._has_cat:
            return self._run(["cat", str(target)])
        if not target.is_file():
            raise FileNotFoundError(str(target))
        return self._clip(target.read_text(encoding="utf-8", errors="ignore"))

    def sed(self, path: str, start_line: int, end_line: int) -> str:
        if end_line < start_line:
            raise ValueError("end_line must be >= start_line")
        target = self._resolve_path(path)
        if self._has_sed:
            return self._run(["sed", "-n", f"{start_line},{end_line}p", str(target)])
        if not target.is_file():
            raise FileNotFoundError(str(target))
        lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), end_line)
        return self._clip("\n".join(lines[start_idx:end_idx]))
