# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from .c_family_nodes import (
    _Reference,
    _identifier_from_node,
    _node_child_by_field_name,
    _node_children,
    _node_kind,
    _node_line,
)


class CFamilyAstMixin:
    def _iter_nodes(self, root):
        if root is None:
            return
        stack = [root]
        while stack:
            node = stack.pop()
            yield node
            for child in reversed(_node_children(node)):
                stack.append(child)

    def _iter_function_definitions(self, root, *, include_methods: bool = False):
        for node in self._iter_nodes(root):
            node_kind = _node_kind(node)
            if node_kind == "function_definition" or (
                include_methods and node_kind == "method_definition"
            ):
                yield node

    def _function_name_from_definition(self, node, source: bytes) -> str:
        declarator = _node_child_by_field_name(node, "declarator")
        return _identifier_from_node(declarator or node, source)

    def _collect_calls_in_scope(
        self,
        scope_node,
        source: bytes,
        *,
        exclude_symbols=None,
    ) -> list[_Reference]:
        out: list[_Reference] = []
        if scope_node is None:
            return out
        exclude_symbols = frozenset(exclude_symbols or ())

        for node in self._iter_nodes(scope_node):
            if _node_kind(node) != "call_expression":
                continue
            function_node = _node_child_by_field_name(node, "function")
            symbol = _identifier_from_node(function_node or node, source)
            if symbol and symbol not in exclude_symbols:
                out.append(_Reference(symbol=symbol, line=_node_line(node)))
        out.sort(key=lambda item: (item.line, item.symbol.lower()))
        return out
