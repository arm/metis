# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ParsedUnit:
    text: str
    tree: Any


class TreeSitterRuntime:
    def __init__(self, language_name: str):
        self.language_name = language_name

        self._available = False
        self._parser = None
        self._init_error = ""
        try:
            from tree_sitter_language_pack import get_parser

            get_parser(language_name)
            self._parser = True
            self._available = True
        except Exception as exc:
            self._init_error = (
                f"{exc}. Install a compatible parser pack with: "
                "uv pip install --reinstall --no-cache --link-mode=copy "
                "'tree-sitter-language-pack!=1.6.3,>=1.6.2'"
            )

    @property
    def is_available(self) -> bool:
        return self._available and self._parser is not None

    @property
    def init_error(self) -> str:
        return self._init_error

    def parse_file(self, codebase_path: str, rel_path: str) -> ParsedUnit:
        if not self.is_available:
            raise RuntimeError(
                f"Tree-sitter parser unavailable for '{self.language_name}': {self._init_error or 'unknown error'}"
            )
        from tree_sitter_language_pack import get_parser

        full = (Path(codebase_path) / rel_path).resolve()
        if not full.is_file():
            raise FileNotFoundError(str(full))

        text = full.read_text(encoding="utf-8", errors="ignore")
        parser = get_parser(self.language_name)
        return ParsedUnit(text=text, tree=parser.parse(text))
