# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from metis.engine.source.tree_sitter_nodes import _node_child_by_field_name
from metis.engine.source.tree_sitter_nodes import _node_children
from metis.engine.source.tree_sitter_nodes import _node_kind
from metis.engine.source.tree_sitter_nodes import _node_text

from .runtime import _mask_non_newlines


def header_node_languages(node: Any, source: bytes) -> frozenset[str]:
    """Apply known language guards without guessing other build macros.

    Profiled source has already had inactive lines blanked. On raw source,
    unknown conditions retain both possibilities, including unknown C++ version
    comparisons. Only a definitely inactive branch excludes a language.
    """
    languages = {"c", "cpp"}
    start = int(node.start_byte())
    parent = node.parent()
    while parent is not None and languages:
        kind = _node_kind(parent)
        if kind in {"preproc_ifdef", "preproc_if", "preproc_elif"}:
            alternative = _node_child_by_field_name(parent, "alternative")
            in_alternative = alternative is not None and start >= int(
                alternative.start_byte()
            )
            languages = {
                language
                for language in languages
                if (value := _guard_value(parent, source, language)) is None
                or bool(value) != in_alternative
            }
        parent = parent.parent()
    return frozenset(languages)


def header_source_for_language(
    nodes: tuple[Any, ...], source: bytes, language: str
) -> bytes:
    """Blank definitely inactive branch bodies without shifting source offsets."""
    spans: list[tuple[int, int]] = []
    for node in nodes:
        if _node_kind(node) not in {"preproc_ifdef", "preproc_if", "preproc_elif"}:
            continue
        value = _guard_value(node, source, language)
        alternative = _node_child_by_field_name(node, "alternative")
        if value is None:
            continue
        if value:
            if alternative is not None:
                spans.append(
                    (int(alternative.start_byte()), int(alternative.end_byte()))
                )
            continue
        condition = _node_child_by_field_name(node, "condition") or (
            _node_child_by_field_name(node, "name")
        )
        if condition is None:
            continue
        newline = source.find(b"\n", int(condition.end_byte()))
        if newline < 0:
            continue
        end = (
            int(alternative.start_byte())
            if alternative is not None
            else next(
                (
                    int(child.start_byte())
                    for child in _node_children(node)
                    if _node_kind(child) == "#endif"
                ),
                int(node.end_byte()),
            )
        )
        spans.append((newline + 1, end))
    if not spans:
        return source
    masked = bytearray(source)
    masked_until = 0
    for start, end in sorted(spans):
        _mask_non_newlines(masked, source, max(start, masked_until), end)
        masked_until = max(masked_until, end)
    return bytes(masked)


def _guard_value(node: Any, source: bytes, language: str) -> int | None:
    if _node_kind(node) == "preproc_ifdef":
        name = _node_child_by_field_name(node, "name")
        if _node_text(name, source) != "__cplusplus":
            return None
        directive = _node_text(node.child(0), source)
        return int((language == "cpp") == (directive == "#ifdef"))
    return _condition_value(
        _node_child_by_field_name(node, "condition"), source, language, boolean=True
    )


def _condition_value(
    node: Any, source: bytes, language: str, depth: int = 0, *, boolean: bool = False
) -> int | None:
    if node is None or depth >= 32:
        return None
    kind = _node_kind(node)
    if kind == "identifier":
        if _node_text(node, source) != "__cplusplus":
            return None
        return 0 if language == "c" else (1 if boolean else None)
    if kind == "preproc_defined":
        names = [c for c in _node_children(node) if _node_kind(c) == "identifier"]
        return (
            _condition_value(names[0], source, language, depth + 1, boolean=True)
            if names
            else None
        )
    if kind == "number_literal":
        text = _node_text(node, source)
        if len(text) > 128:
            return None
        try:
            return int(text.rstrip("uUlL"), 0)
        except ValueError:
            return None
    if kind == "parenthesized_expression":
        children = [
            c
            for c in _node_children(node)
            if _node_kind(c) not in {"(", ")", "comment"}
        ]
        return (
            _condition_value(children[0], source, language, depth + 1, boolean=boolean)
            if len(children) == 1
            else None
        )
    operator = _node_text(_node_child_by_field_name(node, "operator"), source)
    if kind == "unary_expression" and operator == "!":
        value = _condition_value(
            _node_child_by_field_name(node, "argument"),
            source,
            language,
            depth + 1,
            boolean=True,
        )
        return int(not value) if value is not None else None
    if kind != "binary_expression":
        return None
    left = _condition_value(
        _node_child_by_field_name(node, "left"),
        source,
        language,
        depth + 1,
        boolean=operator in {"&&", "||"},
    )
    right = _condition_value(
        _node_child_by_field_name(node, "right"),
        source,
        language,
        depth + 1,
        boolean=operator in {"&&", "||"},
    )
    return _binary_condition_value(operator, left, right)


def _binary_condition_value(
    operator: str, left: int | None, right: int | None
) -> int | None:
    if operator == "&&":
        if left == 0 or right == 0:
            return 0
        return (
            int(bool(left and right))
            if left is not None and right is not None
            else None
        )
    if operator == "||":
        if left or right:
            return 1
        return 0 if left == 0 and right == 0 else None
    if left is None or right is None:
        return None
    comparisons = {
        "==": left == right,
        "!=": left != right,
        "<": left < right,
        "<=": left <= right,
        ">": left > right,
        ">=": left >= right,
    }
    return int(comparisons[operator]) if operator in comparisons else None
