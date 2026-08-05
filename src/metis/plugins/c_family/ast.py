# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from metis.engine.source.tree_sitter_nodes import (
    _identifier_from_node,
    _node_child_by_field_name,
    _node_children,
    _node_kind,
    _node_line,
    _node_text,
)

ANONYMOUS_NAMESPACE_SCOPE = "(anonymous namespace)"


@dataclass(frozen=True, slots=True)
class CFamilyCallSite:
    symbol: str
    line: int
    argument_count: int
    qualified_name: str = ""
    generic_qualified_name: str = ""
    receiver: str = ""


@dataclass(frozen=True, slots=True)
class CFamilyFunctionSyntax:
    name: str
    qualified_name: str
    signature_suffix: str
    lexical_scope: tuple[str, ...]
    minimum_argument_count: int
    maximum_argument_count: int | None


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

    def _has_anonymous_namespace_ancestor(self, node: Any) -> bool:
        parent = node.parent() if node is not None else None
        while parent is not None:
            if _is_anonymous_namespace(parent):
                return True
            parent = parent.parent()
        return False

    def _function_syntax(
        self,
        node: Any,
        source: bytes,
    ) -> CFamilyFunctionSyntax | None:
        declarator = _find_function_declarator(
            _node_child_by_field_name(node, "declarator")
        )
        if declarator is None:
            return None
        name_node = _node_child_by_field_name(declarator, "declarator")
        if name_node is None:
            return None
        declared_name = _normalized_syntax(_node_text(name_node, source))
        name = _callable_name(name_node, source)
        if not declared_name or not name:
            return None
        lexical_scope = _lexical_scope(node, source)
        unqualified_declared_name = declared_name.removeprefix("::")
        scope_prefix = "::".join(lexical_scope)
        if not scope_prefix or declared_name.startswith("::"):
            qualified_name = unqualified_declared_name
        elif unqualified_declared_name.startswith(f"{scope_prefix}::"):
            qualified_name = unqualified_declared_name
        else:
            qualified_name = f"{scope_prefix}::{unqualified_declared_name}"
        parameters = _node_child_by_field_name(declarator, "parameters")
        minimum_argument_count, maximum_argument_count = _parameter_arity(
            parameters, source
        )
        parameter_types = _parameter_types(parameters, source)
        trailing = _normalized_syntax(
            source[int(parameters.end_byte()) : int(declarator.end_byte())].decode(
                "utf-8", errors="ignore"
            )
            if parameters is not None
            else ""
        )
        signature_suffix = f"({','.join(parameter_types)}){trailing}"
        return CFamilyFunctionSyntax(
            name=name,
            qualified_name=qualified_name,
            signature_suffix=signature_suffix,
            lexical_scope=tuple(qualified_name.split("::")[:-1]),
            minimum_argument_count=minimum_argument_count,
            maximum_argument_count=maximum_argument_count,
        )

    def _collect_calls_in_scope(
        self,
        scope_node: Any,
        source: bytes,
        *,
        exclude_symbols: set[str] | frozenset[str] | None = None,
        include_constructors: bool = False,
        legacy_identifiers: bool = False,
    ) -> list[CFamilyCallSite]:
        out: list[CFamilyCallSite] = []
        if scope_node is None:
            return out
        exclude_symbols = frozenset(exclude_symbols or ())

        for node in self._iter_nodes(scope_node):
            node_kind = _node_kind(node)
            if include_constructors and node_kind == "new_expression":
                if _node_child_by_field_name(node, "declarator") is None:
                    constructor = _constructor_call_site(
                        node,
                        _node_child_by_field_name(node, "type"),
                        _node_child_by_field_name(node, "arguments"),
                        source,
                    )
                    if constructor is not None:
                        out.append(constructor)
                continue
            if include_constructors and node_kind == "compound_literal_expression":
                constructor = _constructor_call_site(
                    node,
                    _node_child_by_field_name(node, "type"),
                    _node_child_by_field_name(node, "value"),
                    source,
                )
                if constructor is not None:
                    out.append(constructor)
                continue
            if include_constructors and node_kind == "declaration":
                out.extend(_declaration_constructor_calls(node, source))
                continue
            if node_kind != "call_expression":
                continue
            function_node = _node_child_by_field_name(node, "function")
            symbol = (
                _identifier_from_node(function_node or node, source)
                if legacy_identifiers
                else _callable_name(function_node or node, source)
            )
            if symbol and symbol not in exclude_symbols:
                function_kind = _node_kind(function_node)
                qualified_name, generic_qualified_name = (
                    _qualified_callable_names(function_node, source)
                    if not legacy_identifiers
                    and function_kind == "qualified_identifier"
                    else ("", "")
                )
                receiver = ""
                if not legacy_identifiers and function_kind == "field_expression":
                    receiver = _normalized_syntax(
                        _node_text(
                            _node_child_by_field_name(function_node, "argument"),
                            source,
                        )
                    )
                arguments = _node_child_by_field_name(node, "arguments")
                out.append(
                    CFamilyCallSite(
                        symbol=symbol,
                        line=_node_line(node),
                        argument_count=_argument_count(arguments),
                        qualified_name=qualified_name,
                        generic_qualified_name=generic_qualified_name,
                        receiver=receiver,
                    )
                )
        out.sort(
            key=lambda item: (
                item.line,
                item.symbol.lower(),
                item.qualified_name,
                item.generic_qualified_name,
                item.receiver,
            )
        )
        return out


def _find_function_declarator(node: Any) -> Any | None:
    stack = [node] if node is not None else []
    while stack:
        current = stack.pop()
        if _node_kind(current) == "function_declarator":
            return current
        nested = _node_child_by_field_name(current, "declarator")
        if nested is not None:
            stack.append(nested)
            continue
        stack.extend(reversed(_node_children(current)))
    return None


def _callable_name(node: Any, source: bytes) -> str:
    current = node
    while current is not None:
        kind = _node_kind(current)
        if kind in {
            "qualified_identifier",
            "field_expression",
            "template_function",
            "template_method",
            "template_type",
        }:
            nested = _node_child_by_field_name(current, "name")
            if nested is None and kind == "field_expression":
                nested = _node_child_by_field_name(current, "field")
            if nested is not None:
                current = nested
                continue
        if kind in {
            "destructor_name",
            "operator_name",
            "identifier",
            "field_identifier",
            "namespace_identifier",
            "type_identifier",
        }:
            return _normalized_syntax(_node_text(current, source))
        break
    return _identifier_from_node(node, source)


def _lexical_scope(node: Any, source: bytes) -> tuple[str, ...]:
    scopes: list[str] = []
    parent = node.parent() if node is not None else None
    while parent is not None:
        if _node_kind(parent) in {
            "namespace_definition",
            "class_specifier",
            "struct_specifier",
            "union_specifier",
        }:
            name_node = _node_child_by_field_name(parent, "name")
            if _is_anonymous_namespace(parent):
                name = ANONYMOUS_NAMESPACE_SCOPE
            elif name_node is not None:
                name = _normalized_syntax(_node_text(name_node, source))
            else:
                name = ""
            if name:
                scopes.append(name)
        parent = parent.parent()
    scopes.reverse()
    return tuple(scopes)


def _qualified_callable_names(node: Any, source: bytes) -> tuple[str, str]:
    return (
        _qualified_syntax_name(node, source, erase_template_types=False),
        _qualified_syntax_name(node, source, erase_template_types=True),
    )


def _qualified_syntax_name(
    node: Any,
    source: bytes,
    *,
    erase_template_types: bool,
) -> str:
    if node is None:
        return ""
    kind = _node_kind(node)
    if kind == "qualified_identifier":
        scope = _qualified_syntax_name(
            _node_child_by_field_name(node, "scope"),
            source,
            erase_template_types=erase_template_types,
        )
        name = _qualified_syntax_name(
            _node_child_by_field_name(node, "name"),
            source,
            erase_template_types=erase_template_types,
        )
        qualified = f"{scope}::{name}" if scope and name else name
        if _normalized_syntax(_node_text(node, source)).startswith("::"):
            return f"::{qualified}"
        return qualified
    if kind == "template_type":
        if not erase_template_types:
            return _normalized_syntax(_node_text(node, source))
        return _qualified_syntax_name(
            _node_child_by_field_name(node, "name"),
            source,
            erase_template_types=True,
        )
    if kind in {"template_function", "template_method"}:
        return _qualified_syntax_name(
            _node_child_by_field_name(node, "name"),
            source,
            erase_template_types=erase_template_types,
        )
    return _normalized_syntax(_node_text(node, source))


def _is_anonymous_namespace(node: Any) -> bool:
    return _node_kind(node) == "namespace_definition" and not bool(
        _node_child_by_field_name(node, "name")
    )


def _parameter_values(node: Any) -> list[Any]:
    if node is None:
        return []
    return [
        child
        for child in _node_children(node)
        if _node_kind(child) not in {"(", ")", ",", "comment"}
    ]


def _parameter_arity(node: Any, source: bytes) -> tuple[int, int | None]:
    values = _parameter_values(node)
    if len(values) == 1 and _normalized_syntax(_node_text(values[0], source)) == "void":
        return 0, 0
    variadic_kinds = {
        "variadic_parameter",
        "variadic_parameter_declaration",
        "...",
    }
    variadic = any(
        _node_kind(child) in variadic_kinds
        or _normalized_syntax(_node_text(child, source)) == "..."
        for child in values
    )
    parameters = [child for child in values if _node_kind(child) not in variadic_kinds]
    minimum = sum(
        _node_kind(child) != "optional_parameter_declaration" for child in parameters
    )
    return minimum, None if variadic else len(parameters)


def _parameter_types(node: Any, source: bytes) -> tuple[str, ...]:
    values = _parameter_values(node)
    if len(values) == 1 and _normalized_syntax(_node_text(values[0], source)) == "void":
        return ()
    return tuple(_parameter_type(value, source) for value in values)


def _parameter_type(node: Any, source: bytes) -> str:
    if _node_kind(node) in {"variadic_parameter", "..."}:
        return "..."
    start = int(node.start_byte())
    end = int(node.end_byte())
    excluded: list[tuple[int, int]] = []
    declarator = _node_child_by_field_name(node, "declarator")
    name_node = _declarator_name_node(declarator)
    if name_node is not None:
        excluded.append((int(name_node.start_byte()), int(name_node.end_byte())))
    default = _node_child_by_field_name(node, "default_value")
    if default is not None:
        excluded.append((int(default.start_byte()), int(default.end_byte())))
    declarator_kind = _node_kind(declarator) if declarator is not None else ""
    if declarator_kind in {"", "identifier"}:
        excluded.extend(
            (int(child.start_byte()), int(child.end_byte()))
            for child in _node_children(node)
            if _node_kind(child) == "type_qualifier"
        )
    elif declarator_kind == "pointer_declarator":
        top_level_pointer = declarator
        nested = _node_child_by_field_name(top_level_pointer, "declarator")
        while nested is not None and _node_kind(nested) == "pointer_declarator":
            top_level_pointer = nested
            nested = _node_child_by_field_name(top_level_pointer, "declarator")
        excluded.extend(
            (int(child.start_byte()), int(child.end_byte()))
            for child in _node_children(top_level_pointer)
            if _node_kind(child) == "type_qualifier"
        )
    parts: list[bytes] = []
    cursor = start
    for excluded_start, excluded_end in sorted(excluded):
        parts.append(source[cursor:excluded_start])
        cursor = excluded_end
    parts.append(source[cursor:end])
    value = b"".join(parts).decode("utf-8", errors="ignore")
    normalized = _normalized_syntax(re.sub(r"=\s*$", "", value))
    adjusted_declarator = declarator
    while (
        adjusted_declarator is not None
        and _node_kind(adjusted_declarator) == "array_declarator"
    ):
        adjusted_declarator = _node_child_by_field_name(
            adjusted_declarator, "declarator"
        )
    if declarator_kind != "array_declarator" or (
        adjusted_declarator is not None
        and _node_kind(adjusted_declarator) == "parenthesized_declarator"
    ):
        return normalized
    dimensions = re.findall(r"\[[^]]*\]", normalized)
    element_type = normalized.split("[", 1)[0]
    if len(dimensions) <= 1:
        return f"{element_type}*"
    return f"{element_type}(*){''.join(dimensions[1:])}"


def _declarator_name_node(node: Any) -> Any | None:
    stack = [node] if node is not None else []
    while stack:
        current = stack.pop()
        if _node_kind(current) in {"identifier", "field_identifier"}:
            return current
        stack.extend(reversed(_node_children(current)))
    return None


def _argument_count(node: Any) -> int:
    if node is None:
        return 0
    return sum(
        _node_kind(child) not in {"(", ")", "{", "}", ",", "comment"}
        for child in _node_children(node)
    )


def _declaration_constructor_calls(
    node: Any,
    source: bytes,
) -> list[CFamilyCallSite]:
    type_node = _node_child_by_field_name(node, "type")
    calls: list[CFamilyCallSite] = []
    for declarator in _node_children(node):
        if _node_kind(declarator) != "init_declarator":
            continue
        arguments = _node_child_by_field_name(declarator, "value")
        if _node_kind(arguments) not in {"argument_list", "initializer_list"}:
            continue
        call = _constructor_call_site(declarator, type_node, arguments, source)
        if call is not None:
            calls.append(call)
    return calls


def _constructor_call_site(
    node: Any,
    type_node: Any,
    arguments: Any,
    source: bytes,
) -> CFamilyCallSite | None:
    if _node_kind(type_node) not in {
        "qualified_identifier",
        "template_type",
        "type_identifier",
    }:
        return None
    symbol = _callable_name(type_node, source)
    type_name = _normalized_syntax(_node_text(type_node, source))
    generic_type_name = _qualified_syntax_name(
        type_node,
        source,
        erase_template_types=True,
    )
    if not symbol or not type_name:
        return None
    return CFamilyCallSite(
        symbol=symbol,
        line=_node_line(node),
        argument_count=_argument_count(arguments),
        qualified_name=f"{type_name}::{symbol}",
        generic_qualified_name=f"{generic_type_name}::{symbol}",
    )


def _normalized_syntax(value: str) -> str:
    normalized = " ".join(str(value or "").split())
    normalized = re.sub(r"\s*::\s*", "::", normalized)
    normalized = re.sub(r"\s*([(),<>\[\]])\s*", r"\1", normalized)
    return re.sub(r"\s*([*&]+)\s*", r"\1", normalized)
