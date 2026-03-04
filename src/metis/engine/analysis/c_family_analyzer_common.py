# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def _node_text(node, source: bytes) -> str:
    start = getattr(node, "start_byte", 0)
    end = getattr(node, "end_byte", 0)
    try:
        return source[start:end].decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _identifier_from_node(node, source: bytes) -> str:
    if node is None:
        return ""
    node_type = str(getattr(node, "type", "") or "")
    if node_type in {"identifier", "field_identifier"}:
        return _node_text(node, source).strip()
    for child in getattr(node, "children", []) or []:
        ident = _identifier_from_node(child, source)
        if ident:
            return ident
    return ""


def _node_line(node: Any) -> int:
    return int(getattr(node, "start_point", (0, 0))[0]) + 1


def _node_end_line(node: Any) -> int:
    end = getattr(node, "end_point", None)
    if isinstance(end, tuple) and len(end) >= 1:
        return int(end[0]) + 1
    return _node_line(node)


@dataclass(frozen=True)
class _Definition:
    symbol: str
    line: int


@dataclass(frozen=True)
class _Reference:
    symbol: str
    line: int


@dataclass(frozen=True)
class _FlowHop:
    role: str
    line: int
    detail: str
    symbol: str = ""


@dataclass(frozen=True)
class _FunctionInfo:
    name: str
    line_start: int
    line_end: int
    node: Any
    calls: list[_Reference]
    checks: list[_FlowHop]


@dataclass(frozen=True)
class _CrossFileHit:
    symbol: str
    file_path: str
    line: int
    kind: str
