# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import asdict, dataclass, field, fields

KIND_FUNCTION = "function"
KIND_STATEMENT = "statement"
KIND_RANGE = "range"
KIND_CHUNK = "chunk"

CONFIDENCE_EXACT = "exact"
CONFIDENCE_DISAMBIGUATED = "disambiguated"
CONFIDENCE_FUZZY = "fuzzy"
CONFIDENCE_UNRESOLVED = "unresolved"

_HASH_LEN = 16
_WS_RUN = re.compile(r"\s+")


def normalize_path(path: str | None) -> str:
    return os.path.normpath(str(path or "")).replace("\\", "/").lstrip("./")


def content_hash(text: str) -> str:
    normalized = _WS_RUN.sub(" ", text.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:_HASH_LEN]


@dataclass(frozen=True)
class CodeAnchor:
    """
    A precise, self-validating reference to a span of source code.

    ``stable_id()`` is the join key for graph nodes, memory entries and
    findings: it omits line numbers so unrelated edits above the span do not
    invalidate the reference, while ``content_hash`` lets callers detect when
    the referenced code itself has changed.
    """

    file_path: str
    start_line: int
    end_line: int
    start_col: int = 0
    end_col: int = 0
    start_byte: int = 0
    end_byte: int = 0
    symbol: str | None = None
    kind: str = KIND_RANGE
    content_hash: str = ""
    confidence: str = CONFIDENCE_EXACT

    _FIELD_NAMES: frozenset[str] = field(
        default=frozenset(), init=False, repr=False, compare=False
    )

    def __post_init__(self):
        object.__setattr__(self, "file_path", normalize_path(self.file_path))
        object.__setattr__(
            self, "_FIELD_NAMES", frozenset(f.name for f in fields(self) if f.init)
        )

    def display_id(self) -> str:
        sym = self.symbol or ""
        return f"{self.file_path}#{sym}@{self.start_line}-{self.end_line}"

    def stable_id(self) -> str:
        sym = self.symbol or "<file>"
        return f"{self.file_path}#{sym}~{self.content_hash}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("_FIELD_NAMES", None)
        return d

    @classmethod
    def from_dict(cls, data: dict | None) -> "CodeAnchor | None":
        if not isinstance(data, dict):
            return None
        names = {f.name for f in fields(cls) if f.init}
        return cls(**{k: v for k, v in data.items() if k in names})

    @classmethod
    def unresolved(cls, file_path: str, *, symbol: str | None = None) -> "CodeAnchor":
        return cls(
            file_path=file_path,
            start_line=0,
            end_line=0,
            symbol=symbol,
            confidence=CONFIDENCE_UNRESOLVED,
        )
