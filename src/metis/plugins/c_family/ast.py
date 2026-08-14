# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import replace
from typing import Any

from metis.engine.codegraph import CallKind
from metis.engine.codegraph import CodeExpression
from metis.engine.codegraph import ControlCondition
from metis.engine.codegraph import FunctionParameter
from metis.engine.codegraph import LoopStructure
from metis.engine.codegraph import NullCondition
from metis.engine.codegraph import NullFact
from metis.engine.codegraph import ReturnSite
from metis.engine.codegraph import ValueAssignment
from metis.engine.source.tree_sitter_nodes import (
    _identifier_from_node,
    _node_child_by_field_name,
    _node_children,
    _node_kind,
    _node_line,
    _node_text,
)

from .runtime import _scan_invocation

ANONYMOUS_NAMESPACE_SCOPE = "(anonymous namespace)"
_UNEVALUATED_EXPRESSION_KINDS = frozenset(
    ("alignof_expression", "decltype", "sizeof_expression")
)


@dataclass(frozen=True, slots=True)
class CFamilyCallSite:
    symbol: str
    precise_symbol: str
    line: int
    argument_count: int
    kind: CallKind
    start_byte: int
    end_byte: int
    qualified_name: str = ""
    generic_qualified_name: str = ""
    receiver: str = ""
    arguments: tuple[CodeExpression, ...] = ()
    conditions: tuple[ControlCondition, ...] = ()
    must_conditions: tuple[ControlCondition, ...] = ()
    result: CodeExpression | None = None
    lexical_argument_spans: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True, slots=True)
class CFamilyFunctionSyntax:
    name: str
    qualified_name: str
    signature_suffix: str
    lexical_scope: tuple[str, ...]
    parameters: tuple[FunctionParameter, ...]
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
        parameter_metadata = _parameters(parameters, source)
        trailing = _normalized_syntax(
            source[int(parameters.end_byte()) : int(declarator.end_byte())].decode(
                "utf-8", errors="ignore"
            )
            if parameters is not None
            else ""
        )
        signature_suffix = (
            f"({','.join(item.type_spelling for item in parameter_metadata)}){trailing}"
        )
        return CFamilyFunctionSyntax(
            name=name,
            qualified_name=qualified_name,
            signature_suffix=signature_suffix,
            lexical_scope=tuple(qualified_name.split("::")[:-1]),
            parameters=parameter_metadata,
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
        scope_nodes: tuple[Any, ...] | None = None,
    ) -> list[CFamilyCallSite]:
        out: list[CFamilyCallSite] = []
        if scope_node is None:
            return out
        exclude_symbols = frozenset(exclude_symbols or ())

        for node in scope_nodes or self._iter_nodes(scope_node):
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
            precise_symbol = _callable_name(function_node or node, source)
            symbol = _identifier_from_node(function_node or node, source)
            if not legacy_identifiers:
                symbol = precise_symbol
            if symbol and symbol not in exclude_symbols:
                function_kind = _node_kind(function_node)
                qualified_name, generic_qualified_name = (
                    _qualified_callable_names(function_node, source)
                    if function_kind == "qualified_identifier"
                    else ("", "")
                )
                receiver = ""
                if function_kind == "field_expression":
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
                        precise_symbol=precise_symbol or symbol,
                        line=_node_line(node),
                        argument_count=_argument_count(arguments),
                        kind=self._call_kind(
                            function_node,
                            source,
                            language_is_c=legacy_identifiers,
                        ),
                        start_byte=int(node.start_byte()),
                        end_byte=int(node.end_byte()),
                        qualified_name=qualified_name,
                        generic_qualified_name=generic_qualified_name,
                        receiver=receiver,
                        arguments=_argument_expressions(arguments, source),
                        conditions=_enclosing_conditions(node, scope_node, source),
                        must_conditions=_preceding_must_conditions(
                            node,
                            scope_node,
                            source,
                        ),
                        result=_call_result(node, scope_node, source),
                        lexical_argument_spans=_lexical_argument_spans(
                            arguments,
                            source,
                        ),
                    )
                )
        out.sort(
            key=lambda item: (
                item.line,
                item.symbol.lower(),
                item.qualified_name,
                item.generic_qualified_name,
                item.receiver,
                item.start_byte,
            )
        )
        return out

    def _collect_value_assignments(
        self,
        scope_node: Any,
        source: bytes,
        scope_nodes: tuple[Any, ...] | None = None,
    ) -> list[ValueAssignment]:
        assignments: list[ValueAssignment] = []
        for node in scope_nodes or self._iter_nodes(scope_node):
            kind = _node_kind(node)
            if kind == "assignment_expression":
                target_node = _node_child_by_field_name(node, "left")
                value_node = _node_child_by_field_name(node, "right")
                operator = _normalized_syntax(
                    _node_text(_node_child_by_field_name(node, "operator"), source)
                )
            elif kind == "init_declarator":
                declarator = _node_child_by_field_name(node, "declarator")
                target_node = _declarator_name_node(declarator) or declarator
                value_node = _node_child_by_field_name(node, "value")
                operator = "="
            else:
                continue
            target = _code_expression(target_node, source)
            value = _code_expression(value_node, source)
            if target is None or value is None or not operator:
                continue
            assignments.append(
                ValueAssignment(
                    target=target,
                    value=value,
                    operator=operator,
                    line=_node_line(node),
                    start_byte=int(node.start_byte()),
                    end_byte=int(node.end_byte()),
                    conditions=_enclosing_conditions(node, scope_node, source),
                )
            )
        assignments.sort(key=lambda item: (item.start_byte, item.end_byte))
        return assignments

    def _collect_loop_structures(
        self,
        scope_node: Any,
        source: bytes,
        scope_nodes: tuple[Any, ...] | None = None,
    ) -> list[LoopStructure]:
        loops: list[LoopStructure] = []
        loop_kinds = {
            "do_statement",
            "for_range_loop",
            "for_statement",
            "while_statement",
        }
        for node in scope_nodes or self._iter_nodes(scope_node):
            kind = _node_kind(node)
            if kind not in loop_kinds:
                continue
            condition_node = _node_child_by_field_name(node, "condition")
            if condition_node is None and kind == "for_range_loop":
                condition_node = _node_child_by_field_name(node, "right")
            condition = _condition_expression(condition_node, source)
            loops.append(
                LoopStructure(
                    condition=condition,
                    line=_node_line(node),
                    start_byte=int(node.start_byte()),
                    end_byte=int(node.end_byte()),
                    written_identifiers=_written_identifiers(node, source),
                    addressed_identifiers=_addressed_identifiers(node, source),
                )
            )
        loops.sort(key=lambda item: (item.start_byte, item.end_byte))
        return loops

    def _collect_return_sites(
        self,
        scope_node: Any,
        source: bytes,
        scope_nodes: tuple[Any, ...] | None = None,
    ) -> list[ReturnSite]:
        returns: list[ReturnSite] = []
        for node in scope_nodes or self._iter_nodes(scope_node):
            if _node_kind(node) != "return_statement" or _nested_callable_return(
                node,
                scope_node,
            ):
                continue
            value_node = _unwrap_condition_value(_return_value_node(node))
            value = _code_expression(value_node, source)
            returns.append(
                ReturnSite(
                    value=value,
                    line=_node_line(node),
                    start_byte=int(node.start_byte()),
                    end_byte=int(node.end_byte()),
                    conditions=_enclosing_conditions(node, scope_node, source),
                    returns_null=_is_null_literal(value_node, source),
                )
            )
        returns.sort(key=lambda item: (item.start_byte, item.end_byte))
        return returns

    def _call_kind(
        self,
        function_node: Any,
        source: bytes,
        *,
        language_is_c: bool,
    ) -> CallKind:
        function_kind = _node_kind(function_node)
        if function_kind == "field_expression":
            return "indirect" if language_is_c else "member"
        if function_kind == "pointer_expression":
            return "indirect"
        if function_kind == "parenthesized_expression":
            for candidate in self._iter_nodes(function_node):
                if _node_kind(candidate) != "pointer_expression":
                    continue
                operator = _node_child_by_field_name(candidate, "operator")
                if _node_text(operator, source).strip() == "*":
                    return "indirect"
        return "direct"


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


def _expression_children(node: Any) -> list[Any]:
    return [
        child
        for child in _node_children(node)
        if _node_kind(child) not in {"(", ")", "{", "}", ",", "comment"}
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


def _parameters(node: Any, source: bytes) -> tuple[FunctionParameter, ...]:
    values = _parameter_values(node)
    if len(values) == 1 and _normalized_syntax(_node_text(values[0], source)) == "void":
        return ()
    parameters: list[FunctionParameter] = []
    for value in values:
        declarator = _node_child_by_field_name(value, "declarator")
        name_node = _declarator_name_node(declarator)
        name = (
            _normalized_syntax(_node_text(name_node, source))
            if name_node is not None
            else ""
        )
        parameters.append(
            FunctionParameter(
                name=name,
                type_spelling=_parameter_type(value, source),
            )
        )
    return tuple(parameters)


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


def _argument_expressions(
    node: Any,
    source: bytes,
) -> tuple[CodeExpression, ...]:
    if node is None:
        return ()
    return tuple(
        expression
        for child in _expression_children(node)
        if (expression := _code_expression(child, source)) is not None
    )


def _code_expression(node: Any, source: bytes) -> CodeExpression | None:
    if node is None:
        return None
    text = _normalized_syntax(_node_text(node, source))
    if not text:
        return None
    identifiers = tuple(
        dict.fromkeys(
            _normalized_syntax(_node_text(candidate, source))
            for candidate in _walk_value_expression_nodes(node)
            if _node_kind(candidate) == "identifier"
            and _normalized_syntax(_node_text(candidate, source))
        )
    )
    field_paths = tuple(
        dict.fromkeys(
            _normalize_field_path(_node_text(candidate, source))
            for candidate in _walk_value_expression_nodes(node)
            if _node_kind(candidate) == "field_expression"
            and _normalize_field_path(_node_text(candidate, source))
        )
    )
    direct_field_path = _direct_field_path(node, source)
    return CodeExpression(
        text=text,
        line=_node_line(node),
        start_byte=int(node.start_byte()),
        end_byte=int(node.end_byte()),
        identifiers=identifiers,
        field_paths=field_paths,
        direct_identifier=_direct_identifier(node, source),
        direct_field_path=direct_field_path,
    )


def _condition_expression(node: Any, source: bytes) -> CodeExpression | None:
    current = node
    while current is not None and _node_kind(current) == "parenthesized_expression":
        children = _expression_children(current)
        current = children[0] if len(children) == 1 else current
        if current is node:
            break
    return _code_expression(current, source)


def _enclosing_conditions(
    node: Any,
    scope_node: Any,
    source: bytes,
) -> tuple[ControlCondition, ...]:
    conditions: list[ControlCondition] = []
    current = node
    parent = current.parent() if current is not None else None
    while parent is not None and not _same_syntax_node(parent, scope_node):
        kind = _node_kind(parent)
        condition_node: Any | None = None
        truth = True
        if kind in {"if_statement", "conditional_expression"}:
            condition_node = _node_child_by_field_name(parent, "condition")
            alternative = _node_child_by_field_name(parent, "alternative")
            truth = not _contains_node(alternative, current)
        if _contains_node(condition_node, current):
            condition_node = None
        condition = _condition_expression(condition_node, source)
        if condition is not None:
            conditions.append(
                ControlCondition(
                    condition,
                    truth,
                    _null_condition(condition_node, source),
                )
            )
        current = parent
        parent = current.parent()
    conditions.reverse()
    return tuple(conditions)


def _preceding_must_conditions(
    node: Any,
    scope_node: Any,
    source: bytes,
) -> tuple[ControlCondition, ...]:
    if any(
        _node_kind(candidate) in {"goto_statement", "labeled_statement"}
        for candidate in _walk_expression_nodes(scope_node)
    ):
        return ()

    conditions: list[ControlCondition] = []
    current = node
    parent = current.parent() if current is not None else None
    loop_kinds = {
        "do_statement",
        "for_range_loop",
        "for_statement",
        "switch_statement",
        "while_statement",
    }
    while parent is not None and not _same_syntax_node(parent, scope_node):
        if _node_kind(parent) in loop_kinds:
            break
        if _node_kind(parent) == "compound_statement":
            for statement in _preceding_siblings(parent, current):
                terminal = _terminal_guard_condition(statement, source)
                if terminal is not None:
                    conditions.append(terminal)
                    continue
                killed = set(_written_identifiers(statement, source))
                killed.update(_addressed_identifiers(statement, source))
                if killed:
                    conditions = [
                        retained
                        for condition in conditions
                        if (retained := _without_null_identifiers(condition, killed))
                        is not None
                    ]
        current = parent
        parent = current.parent()
    return tuple(
        sorted(
            conditions,
            key=lambda condition: (
                condition.expression.start_byte,
                condition.expression.end_byte,
            ),
        )
    )


def _preceding_siblings(parent: Any, current: Any) -> tuple[Any, ...]:
    siblings: list[Any] = []
    for child in _node_children(parent):
        if _contains_node(child, current):
            break
        if _node_kind(child) not in {"{", "}", "comment"}:
            siblings.append(child)
    return tuple(siblings)


def _terminal_guard_condition(
    statement: Any,
    source: bytes,
) -> ControlCondition | None:
    if _node_kind(statement) != "if_statement":
        return None
    if _node_child_by_field_name(statement, "alternative") is not None:
        return None
    consequence = _node_child_by_field_name(statement, "consequence")
    if not _always_returns(consequence):
        return None
    condition_node = _node_child_by_field_name(statement, "condition")
    condition = _condition_expression(condition_node, source)
    null_condition = _null_condition(condition_node, source)
    if condition is None or null_condition is None or not null_condition.when_false:
        return None
    return ControlCondition(condition, False, null_condition)


def _always_returns(statement: Any) -> bool:
    kind = _node_kind(statement)
    if kind == "return_statement":
        return True
    if kind == "compound_statement":
        children = [
            child
            for child in _node_children(statement)
            if _node_kind(child) not in {"{", "}", "comment"}
        ]
        return bool(children) and _always_returns(children[-1])
    if kind != "if_statement":
        return False
    consequence = _node_child_by_field_name(statement, "consequence")
    alternative = _node_child_by_field_name(statement, "alternative")
    return (
        alternative is not None
        and _always_returns(consequence)
        and _always_returns(alternative)
    )


def _without_null_identifiers(
    condition: ControlCondition,
    killed: set[str],
) -> ControlCondition | None:
    null_condition = condition.null_condition
    if null_condition is None:
        return condition
    when_true = tuple(
        fact
        for fact in null_condition.when_true
        if fact.value.direct_identifier not in killed
    )
    when_false = tuple(
        fact
        for fact in null_condition.when_false
        if fact.value.direct_identifier not in killed
    )
    if not when_true and not when_false:
        return None
    return replace(
        condition,
        null_condition=NullCondition(when_true=when_true, when_false=when_false),
    )


def _lexical_argument_spans(
    arguments: Any,
    source: bytes,
) -> tuple[tuple[int, int], ...]:
    if arguments is None:
        return ()
    scanned = _scan_invocation(source, int(arguments.start_byte()))
    if scanned is None or scanned[0] != int(arguments.end_byte()):
        return ()
    spans: list[tuple[int, int]] = []
    for start, end in scanned[1]:
        while start < end and chr(source[start]).isspace():
            start += 1
        while start < end and chr(source[end - 1]).isspace():
            end -= 1
        spans.append((start, end))
    return tuple(spans)


def _call_result(
    call_node: Any,
    scope_node: Any,
    source: bytes,
) -> CodeExpression | None:
    current = call_node
    parent = current.parent() if current is not None else None
    transparent = {
        "cast_expression",
        "parenthesized_expression",
    }
    while parent is not None and not _same_syntax_node(parent, scope_node):
        kind = _node_kind(parent)
        if kind == "assignment_expression" and _contains_node(
            _node_child_by_field_name(parent, "right"), current
        ):
            return _code_expression(
                _node_child_by_field_name(parent, "left"),
                source,
            )
        if kind == "init_declarator" and _contains_node(
            _node_child_by_field_name(parent, "value"), current
        ):
            declarator = _node_child_by_field_name(parent, "declarator")
            return _code_expression(
                _declarator_name_node(declarator) or declarator,
                source,
            )
        if kind not in transparent:
            return None
        current = parent
        parent = current.parent()
    return None


def _return_value_node(node: Any) -> Any | None:
    value = _node_child_by_field_name(node, "value")
    if value is not None:
        return value
    children = [
        child
        for child in _node_children(node)
        if _node_kind(child) not in {"return", ";", "comment"}
    ]
    return children[0] if len(children) == 1 else None


def _null_condition(node: Any, source: bytes) -> NullCondition | None:
    true_facts = _guaranteed_null_facts(node, source, truth=True)
    false_facts = _guaranteed_null_facts(node, source, truth=False)
    if not true_facts and not false_facts:
        return None
    return NullCondition(when_true=true_facts, when_false=false_facts)


def _guaranteed_null_facts(
    node: Any,
    source: bytes,
    *,
    truth: bool,
) -> tuple[NullFact, ...]:
    current = _unwrap_condition_value(node)
    kind = _node_kind(current)
    if kind == "unary_expression":
        operator = _normalized_syntax(
            _node_text(_node_child_by_field_name(current, "operator"), source)
        )
        if operator != "!":
            return ()
        return _guaranteed_null_facts(
            _node_child_by_field_name(current, "argument"),
            source,
            truth=not truth,
        )
    if kind != "binary_expression":
        return ()
    operator = _normalized_syntax(
        _node_text(_node_child_by_field_name(current, "operator"), source)
    )
    left = _node_child_by_field_name(current, "left")
    right = _node_child_by_field_name(current, "right")
    if operator in {"&&", "||"}:
        both_required = (operator == "&&" and truth) or (operator == "||" and not truth)
        if not both_required:
            return ()
        return _deduplicate_null_facts(
            (
                *_guaranteed_null_facts(left, source, truth=truth),
                *_guaranteed_null_facts(right, source, truth=truth),
            )
        )
    if operator not in {"==", "!="}:
        return ()
    left = _unwrap_condition_value(left)
    right = _unwrap_condition_value(right)
    if _is_null_literal(left, source):
        value_node = right
    elif _is_null_literal(right, source):
        value_node = left
    else:
        return ()
    value = _code_expression(value_node, source)
    if value is None or not (value.direct_identifier or value.direct_field_path):
        return ()
    comparison_true_means_null = operator == "=="
    return (NullFact(value=value, is_null=truth == comparison_true_means_null),)


def _deduplicate_null_facts(facts: tuple[NullFact, ...]) -> tuple[NullFact, ...]:
    by_value: dict[tuple[str, str], list[NullFact]] = {}
    for fact in facts:
        key = (fact.value.direct_identifier, fact.value.direct_field_path)
        by_value.setdefault(key, []).append(fact)
    unique: list[NullFact] = []
    for key in sorted(by_value):
        matching = by_value[key]
        null_values = {fact.is_null for fact in matching}
        if len(null_values) != 1:
            return ()
        unique.append(matching[0])
    return tuple(unique)


def _unwrap_condition_value(node: Any) -> Any | None:
    current = node
    while current is not None and _node_kind(current) in {
        "condition_clause",
        "parenthesized_expression",
    }:
        value = _node_child_by_field_name(current, "value")
        if value is not None:
            current = value
            continue
        children = _expression_children(current)
        if len(children) != 1:
            break
        current = children[0]
    return current


def _is_null_literal(node: Any, source: bytes) -> bool:
    if node is None:
        return False
    kind = _node_kind(node)
    text = _normalized_syntax(_node_text(node, source))
    return kind == "null" or text in {"NULL", "nullptr"}


def _nested_callable_return(node: Any, scope_node: Any) -> bool:
    parent = node.parent() if node is not None else None
    while parent is not None and not _same_syntax_node(parent, scope_node):
        if _node_kind(parent) in {
            "function_definition",
            "lambda_expression",
            "method_definition",
        }:
            return True
        parent = parent.parent()
    return False


def _written_identifiers(node: Any, source: bytes) -> tuple[str, ...]:
    written: list[str] = []
    for candidate in _walk_expression_nodes(node):
        kind = _node_kind(candidate)
        target: Any | None = None
        if kind == "assignment_expression":
            target = _node_child_by_field_name(candidate, "left")
        elif kind == "init_declarator":
            target = _declarator_name_node(
                _node_child_by_field_name(candidate, "declarator")
            )
        elif kind == "update_expression":
            target = _node_child_by_field_name(candidate, "argument")
        identifier = _direct_identifier(target, source)
        if identifier:
            written.append(identifier)
    return tuple(sorted(set(written)))


def _addressed_identifiers(node: Any, source: bytes) -> tuple[str, ...]:
    addressed: list[str] = []
    for candidate in _walk_expression_nodes(node):
        if _node_kind(candidate) != "pointer_expression":
            continue
        operator = _node_text(
            _node_child_by_field_name(candidate, "operator"),
            source,
        ).strip()
        if operator != "&":
            continue
        identifier = _direct_identifier(
            _node_child_by_field_name(candidate, "argument"),
            source,
        )
        if identifier:
            addressed.append(identifier)
    return tuple(sorted(set(addressed)))


def _direct_identifier(node: Any, source: bytes) -> str:
    current = node
    while current is not None and _node_kind(current) == "parenthesized_expression":
        children = _expression_children(current)
        current = children[0] if len(children) == 1 else None
    if current is None or _node_kind(current) != "identifier":
        return ""
    return _normalized_syntax(_node_text(current, source))


def _direct_field_path(node: Any, source: bytes) -> str:
    current = node
    while current is not None and _node_kind(current) == "parenthesized_expression":
        children = _expression_children(current)
        current = children[0] if len(children) == 1 else None
    if current is None or _node_kind(current) != "field_expression":
        return ""
    return _normalize_field_path(_node_text(current, source))


def _walk_expression_nodes(node: Any) -> tuple[Any, ...]:
    if node is None:
        return ()
    nodes: list[Any] = []
    stack = [node]
    while stack:
        current = stack.pop()
        nodes.append(current)
        stack.extend(reversed(_node_children(current)))
    return tuple(nodes)


def _walk_value_expression_nodes(node: Any) -> tuple[Any, ...]:
    if node is None:
        return ()
    nodes: list[Any] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if _node_kind(current) in _UNEVALUATED_EXPRESSION_KINDS:
            continue
        nodes.append(current)
        stack.extend(reversed(_node_children(current)))
    return tuple(nodes)


def _contains_node(container: Any, candidate: Any) -> bool:
    if container is None or candidate is None:
        return False
    return int(container.start_byte()) <= int(candidate.start_byte()) and int(
        candidate.end_byte()
    ) <= int(container.end_byte())


def _same_syntax_node(first: Any, second: Any) -> bool:
    if first is None or second is None:
        return first is second
    return (
        _node_kind(first),
        int(first.start_byte()),
        int(first.end_byte()),
    ) == (
        _node_kind(second),
        int(second.start_byte()),
        int(second.end_byte()),
    )


def _normalize_field_path(value: str) -> str:
    normalized = _normalized_syntax(value)
    return re.sub(r"\s*(?:->|\.)\s*", ".", normalized)


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
        precise_symbol=symbol,
        line=_node_line(node),
        argument_count=_argument_count(arguments),
        kind="constructor",
        start_byte=int(node.start_byte()),
        end_byte=int(node.end_byte()),
        qualified_name=f"{type_name}::{symbol}",
        generic_qualified_name=f"{generic_type_name}::{symbol}",
    )


def _normalized_syntax(value: str) -> str:
    normalized = " ".join(str(value or "").split())
    normalized = re.sub(r"\s*::\s*", "::", normalized)
    normalized = re.sub(r"\s*([(),<>\[\]])\s*", r"\1", normalized)
    return re.sub(r"\s*([*&]+)\s*", r"\1", normalized)
