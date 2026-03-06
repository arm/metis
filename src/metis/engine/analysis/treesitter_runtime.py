# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import threading
from typing import Any


@dataclass(frozen=True)
class ParsedUnit:
    text: str
    tree: Any


class TreeSitterRuntime:
    def __init__(self, language_name: str):
        self.language_name = language_name
        self._cache: dict[str, tuple[int, int, str, ParsedUnit]] = {}
        self._lock = threading.Lock()

        self._parser = None
        self._init_error = ""
        try:
            from tree_sitter_language_pack import get_parser

            self._parser = get_parser(language_name)
        except Exception as exc:
            self._init_error = str(exc)

    @property
    def is_available(self) -> bool:
        return self._parser is not None

    @property
    def init_error(self) -> str:
        return self._init_error

    def parse_file(self, codebase_path: str, rel_path: str) -> ParsedUnit:
        if not self.is_available:
            raise RuntimeError(
                f"Tree-sitter parser unavailable for '{self.language_name}': {self._init_error or 'unknown error'}"
            )

        full = (Path(codebase_path) / rel_path).resolve()
        if not full.is_file():
            raise FileNotFoundError(str(full))

        stat = full.stat()
        text = full.read_text(encoding="utf-8", errors="ignore")
        digest = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

        key = full.as_posix()
        with self._lock:
            cached = self._cache.get(key)
            if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
                if cached[2] == digest:
                    return cached[3]

            tree = self._parser.parse(bytes(text, "utf-8"))
            parsed = ParsedUnit(text=text, tree=tree)
            self._cache[key] = (stat.st_mtime_ns, stat.st_size, digest, parsed)
            return parsed
