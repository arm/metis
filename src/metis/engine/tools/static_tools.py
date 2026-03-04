# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Sequence


class StaticToolRunner:
    def __init__(
        self, *, codebase_path: str, timeout_seconds: int = 8, max_chars: int = 16000
    ):
        self.codebase_path = Path(codebase_path).resolve()
        self.timeout_seconds = timeout_seconds
        self.max_chars = max_chars
        self._has_grep = shutil.which("grep") is not None
        self._has_find = shutil.which("find") is not None
        self._has_cat = shutil.which("cat") is not None
        self._has_sed = shutil.which("sed") is not None

    def _resolve_path(self, raw_path: str) -> Path:
        candidate = (self.codebase_path / raw_path).resolve()
        if (
            candidate != self.codebase_path
            and self.codebase_path not in candidate.parents
        ):
            raise ValueError("Path escapes codebase")
        return candidate

    def _run(self, argv: Sequence[str]) -> str:
        proc = subprocess.run(
            list(argv),
            cwd=str(self.codebase_path),
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
        )
        output = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
        output = output.strip()
        if len(output) > self.max_chars:
            return output[: self.max_chars] + "\n...[truncated]"
        return output

    def _clip(self, text: str) -> str:
        if len(text) > self.max_chars:
            return text[: self.max_chars] + "\n...[truncated]"
        return text

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
        if self._has_grep:
            return self._run(["grep", "-REn", "--", pattern, str(target)])

        try:
            regex = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid grep pattern: {exc}") from exc

        lines: list[str] = []
        for file_path in self._iter_files(target):
            rel = file_path.relative_to(self.codebase_path).as_posix()
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
            output = self._run(["find", ".", "-type", "f", "-name", name])
            found: list[str] = []
            for line in (output or "").splitlines():
                item = line.strip()
                if not item or item.startswith("find:"):
                    continue
                if item.startswith("./"):
                    item = item[2:]
                found.append(item.replace("\\", "/"))
        else:
            found = []
            for file_path in self._iter_files(self.codebase_path):
                if file_path.name != name:
                    continue
                try:
                    item = file_path.relative_to(self.codebase_path).as_posix()
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
