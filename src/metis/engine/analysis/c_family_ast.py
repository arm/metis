# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
from typing import Any

from .base import AnalyzerRequest
from .c_family_analyzer_common import (
    _Definition,
    _FlowHop,
    _FunctionInfo,
    _Reference,
    _identifier_from_node,
    _node_end_line,
    _node_line,
    _node_text,
)


class CFamilyAstMixin:
    def _select_wanted_symbols(
        self,
        *,
        definitions: dict[str, list[_Definition]],
        references: dict[str, list[_Reference]],
        calls: dict[str, list[_Reference]],
        request: AnalyzerRequest,
    ) -> list[str]:
        candidates = [
            self._derive_symbols_near_line(
                definitions,
                references,
                calls,
                line=request.line,
                limit=10,
            ),
            [s for s in request.candidate_symbols if s][:8],
            list(definitions.keys())[:6],
        ]
        for symbols in candidates:
            if symbols:
                return symbols
        return []

    def _index_tree(self, root) -> tuple[list[Any], dict[int, Any | None]]:
        nodes: list[Any] = []
        parent_map: dict[int, Any | None] = {}

        def walk(node, parent):
            nodes.append(node)
            parent_map[id(node)] = parent
            for child in getattr(node, "children", []) or []:
                walk(child, node)

        walk(root, None)
        return nodes, parent_map

    def _find_anchor_node(self, nodes: list[Any], line: int):
        best = None
        best_score = 1_000_000
        best_span = 1_000_000
        for node in nodes:
            start = _node_line(node)
            end = _node_end_line(node)
            if start <= line <= end:
                score = 0
                span = max(1, end - start + 1)
            else:
                score = min(abs(start - line), abs(end - line))
                span = max(1, end - start + 1)
            if score < best_score or (score == best_score and span < best_span):
                best = node
                best_score = score
                best_span = span
        return best

    def _nearest_enclosing(
        self, node, parent_map: dict[int, Any | None], types: set[str]
    ):
        cur = node
        while cur is not None:
            if str(getattr(cur, "type", "") or "") in types:
                return cur
            cur = parent_map.get(id(cur))
        return None

    def _collect_guard_hops(
        self, scope_node, source: bytes, line: int
    ) -> list[_FlowHop]:
        guards: list[_FlowHop] = []
        if scope_node is None:
            return guards

        def walk(node):
            node_type = str(getattr(node, "type", "") or "")
            if node_type in {
                "if_statement",
                "while_statement",
                "for_statement",
                "switch_statement",
            }:
                cond = None
                try:
                    cond = node.child_by_field_name("condition")
                except Exception:
                    cond = None
                detail = _identifier_from_node(cond or node, source) or node_type
                guards.append(
                    _FlowHop(
                        role="check", line=_node_line(node), detail=f"guard '{detail}'"
                    )
                )
            for child in getattr(node, "children", []) or []:
                walk(child)

        walk(scope_node)
        guards.sort(key=lambda h: (abs(h.line - line), h.line))
        return guards[:4]

    def _collect_calls_in_scope(self, scope_node, source: bytes) -> list[_Reference]:
        out: list[_Reference] = []
        if scope_node is None:
            return out

        def walk(node):
            node_type = str(getattr(node, "type", "") or "")
            if node_type == "call_expression":
                function_node = None
                try:
                    function_node = node.child_by_field_name("function")
                except Exception:
                    function_node = None
                symbol = _identifier_from_node(function_node or node, source)
                if symbol:
                    out.append(_Reference(symbol=symbol, line=_node_line(node)))
            for child in getattr(node, "children", []) or []:
                walk(child)

        walk(scope_node)
        out.sort(key=lambda item: (item.line, item.symbol.lower()))
        return out

    def _collect_functions(self, root, source: bytes) -> dict[str, list[_FunctionInfo]]:
        out: dict[str, list[_FunctionInfo]] = {}

        def walk(node):
            node_type = str(getattr(node, "type", "") or "")
            if node_type == "function_definition":
                declarator = None
                try:
                    declarator = node.child_by_field_name("declarator")
                except Exception:
                    declarator = None
                name = _identifier_from_node(declarator or node, source)
                if name:
                    info = _FunctionInfo(
                        name=name,
                        line_start=_node_line(node),
                        line_end=_node_end_line(node),
                        node=node,
                        calls=self._collect_calls_in_scope(node, source),
                        checks=self._collect_guard_hops(node, source, _node_line(node)),
                    )
                    out.setdefault(name, []).append(info)
            for child in getattr(node, "children", []) or []:
                walk(child)

        walk(root)
        for name in list(out.keys()):
            out[name] = sorted(out[name], key=lambda f: (f.line_start, f.line_end))
        return out

    def _select_anchor_function(
        self,
        *,
        request_line: int,
        anchor_node,
        parent_map: dict[int, Any | None],
        functions: dict[str, list[_FunctionInfo]],
    ) -> _FunctionInfo | None:
        fn_node = self._nearest_enclosing(
            anchor_node,
            parent_map,
            {"function_definition", "method_definition"},
        )
        if fn_node is not None:
            start = _node_line(fn_node)
            end = _node_end_line(fn_node)
            for variants in functions.values():
                for info in variants:
                    if info.line_start == start and info.line_end == end:
                        return info
        best = None
        best_score = 1_000_000
        for variants in functions.values():
            for info in variants:
                if info.line_start <= request_line <= info.line_end:
                    score = 0
                else:
                    score = min(
                        abs(info.line_start - request_line),
                        abs(info.line_end - request_line),
                    )
                if score < best_score:
                    best = info
                    best_score = score
        return best

    def _derive_symbols_near_line(
        self,
        definitions: dict[str, list[_Definition]],
        references: dict[str, list[_Reference]],
        calls: dict[str, list[_Reference]],
        *,
        line: int,
        limit: int,
    ) -> list[str]:
        scores: dict[str, int] = {}

        def update(symbol: str, distance: int, weight: int):
            if not symbol:
                return
            score = max(0, 200 - min(distance, 200)) + weight
            prev = scores.get(symbol)
            if prev is None or score > prev:
                scores[symbol] = score

        for symbol, items in calls.items():
            for item in items[:8]:
                update(symbol, abs(item.line - line), 40)
        for symbol, items in definitions.items():
            for item in items[:8]:
                update(symbol, abs(item.line - line), 25)
        for symbol, items in references.items():
            for item in items[:8]:
                update(symbol, abs(item.line - line), 10)

        ordered = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0].lower()))
        return [symbol for symbol, _ in ordered[:limit]]

    def _collect_definitions(self, root, source: bytes) -> dict[str, list[_Definition]]:
        out: dict[str, list[_Definition]] = {}

        def add(symbol: str, line: int):
            if not symbol:
                return
            out.setdefault(symbol, []).append(_Definition(symbol=symbol, line=line))

        def walk(node):
            node_type = str(getattr(node, "type", "") or "")
            line = _node_line(node)

            if node_type == "function_definition":
                declarator = None
                try:
                    declarator = node.child_by_field_name("declarator")
                except Exception:
                    declarator = None
                symbol = _identifier_from_node(declarator or node, source)
                add(symbol, line)

            if node_type == "declaration":
                for child in getattr(node, "children", []) or []:
                    if str(getattr(child, "type", "") or "") in {
                        "init_declarator",
                        "function_declarator",
                        "pointer_declarator",
                        "identifier",
                    }:
                        symbol = _identifier_from_node(child, source)
                        add(symbol, line)

            for child in getattr(node, "children", []) or []:
                walk(child)

        walk(root)
        for symbol in list(out.keys()):
            out[symbol] = sorted(out[symbol], key=lambda item: item.line)
        return out

    def _collect_references(self, root, source: bytes) -> dict[str, list[_Reference]]:
        out: dict[str, list[_Reference]] = {}

        def walk(node):
            node_type = str(getattr(node, "type", "") or "")
            if node_type in {"identifier", "field_identifier"}:
                symbol = _node_text(node, source).strip()
                if symbol:
                    line = _node_line(node)
                    out.setdefault(symbol, []).append(
                        _Reference(symbol=symbol, line=line)
                    )
            for child in getattr(node, "children", []) or []:
                walk(child)

        walk(root)
        for symbol in list(out.keys()):
            out[symbol] = sorted(out[symbol], key=lambda item: item.line)
        return out

    def _collect_calls(self, root, source: bytes) -> dict[str, list[_Reference]]:
        out: dict[str, list[_Reference]] = {}

        def walk(node):
            node_type = str(getattr(node, "type", "") or "")
            if node_type == "call_expression":
                function_node = None
                try:
                    function_node = node.child_by_field_name("function")
                except Exception:
                    function_node = None
                symbol = _identifier_from_node(function_node or node, source)
                if symbol:
                    line = _node_line(node)
                    out.setdefault(symbol, []).append(
                        _Reference(symbol=symbol, line=line)
                    )
            for child in getattr(node, "children", []) or []:
                walk(child)

        walk(root)
        for symbol in list(out.keys()):
            out[symbol] = sorted(out[symbol], key=lambda item: item.line)
        return out

    def _is_actionable_symbol(self, symbol: str) -> bool:
        text = str(symbol or "").strip()
        if not text:
            return False
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{1,127}$", text):
            return False
        if text.startswith("__"):
            return False
        if text.isupper():
            return False
        if "_" in text and text.upper() == text:
            return False
        return True

    def _dedup_keep_order(self, values: list[str]) -> list[str]:
        out: list[str] = []
        seen = set()
        for item in values:
            if not item or item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out
