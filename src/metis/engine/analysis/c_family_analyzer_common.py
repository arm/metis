# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def _node_text(node, source: bytes) -> str:
    start = node.start_byte()
    end = node.end_byte()
    try:
        return source[start:end].decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _node_kind(node) -> str:
    return str(node.kind() or "")


def _node_children(node) -> list[Any]:
    return [
        child
        for index in range(node.child_count())
        if (child := node.child(index)) is not None
    ]


def _node_child_by_field_name(node, name: str):
    return node.child_by_field_name(name)


def _identifier_from_node(node, source: bytes) -> str:
    if node is None:
        return ""
    stack = [node]
    while stack:
        current = stack.pop()
        if _node_kind(current) in {"identifier", "field_identifier"}:
            ident = _node_text(current, source).strip()
            if ident:
                return ident
        for child in reversed(_node_children(current)):
            stack.append(child)
    return ""


def _node_line(node: Any) -> int:
    return int(node.start_position().row) + 1


def _node_end_line(node: Any) -> int:
    return int(node.end_position().row) + 1


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
    signature: str
    calls: list[_Reference]
    checks: list[_FlowHop]


@dataclass(frozen=True)
class _CrossFileHit:
    symbol: str
    file_path: str
    line: int
    kind: str
