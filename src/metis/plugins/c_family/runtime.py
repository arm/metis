# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from metis.utils import resolve_path_within_root


_IDENTIFIER_CALL = re.compile(rb"\b[A-Za-z_][A-Za-z0-9_]*[ \t\r\n]*\(")
_IDENTIFIER = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*")
_Span = tuple[int, int]


@dataclass(frozen=True)
class ParsedUnit:
    parse_source: bytes
    tree: Any
    diagnostic_tree: Any
    macro_function_masks: tuple[_MacroFunctionMask, ...] = ()
    macro_function_definitions: tuple[_MacroFunctionDefinition, ...] = ()


@dataclass(frozen=True, slots=True)
class _MacroFunctionDefinition:
    name: str
    parameters: tuple[str, ...]
    referenced_parameter_indexes: frozenset[int]
    passthrough_parameter_index: int | None = None


@dataclass(frozen=True, slots=True)
class _MacroAnnotationArgument:
    index: int
    identifiers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _MacroFunctionMask:
    macro_name: str
    argument_count: int
    invocation_start: int
    invocation_end: int
    declaration_start: int
    declaration_end: int
    name_start: int
    name_end: int
    parameters_start: int
    parameters_end: int
    body_start: int
    annotation_arguments: tuple[_MacroAnnotationArgument, ...]


class TreeSitterRuntime:
    def __init__(self, language_name: str) -> None:
        self.language_name = language_name

        self._available = False
        self._init_error = ""
        try:
            from tree_sitter_language_pack import get_parser

            get_parser(language_name)
            self._available = True
        except Exception as exc:
            self._init_error = str(exc)

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def init_error(self) -> str:
        return self._init_error

    def parse_file(self, codebase_path: str, rel_path: str) -> ParsedUnit:
        if not self.is_available:
            raise RuntimeError(
                f"Tree-sitter parser unavailable for '{self.language_name}': {self._init_error or 'unknown error'}"
            )
        from tree_sitter_language_pack import get_parser

        full = resolve_path_within_root(codebase_path, rel_path)
        if not full.is_file():
            raise FileNotFoundError(str(full))

        source = full.read_bytes()
        parser = get_parser(self.language_name)
        diagnostic_tree = parser.parse_bytes(source)
        parse_source, tree, macro_function_masks = (
            _recover_macro_function_wrappers(parser, source, diagnostic_tree)
            if self.language_name == "c"
            else (source, diagnostic_tree, ())
        )
        return ParsedUnit(
            parse_source=parse_source,
            tree=tree,
            diagnostic_tree=diagnostic_tree,
            macro_function_masks=macro_function_masks,
            macro_function_definitions=(
                _macro_function_definitions(diagnostic_tree, source)
                if self.language_name == "c"
                else ()
            ),
        )


def _recover_macro_function_wrappers(
    parser: Any,
    source: bytes,
    original_tree: Any,
) -> tuple[bytes, Any, tuple[_MacroFunctionMask, ...]]:
    if not original_tree.root_node().has_error():
        return source, original_tree, ()
    masks = _macro_function_masks(parser, source)
    if not masks:
        return source, original_tree, ()

    parse_source = _render_macro_function_masks(source, masks)
    recovered_tree = parser.parse_bytes(parse_source)
    recovered_anchors = _function_anchors(recovered_tree, parse_source)
    expected_anchors = {
        (mask.name_start, mask.name_end, mask.body_start) for mask in masks
    }
    original_anchors = {
        anchor
        for anchor in _function_anchors(original_tree, source)
        if not any(
            mask.invocation_start <= anchor[0] < mask.invocation_end for mask in masks
        )
    }
    if not expected_anchors <= recovered_anchors:
        return source, original_tree, ()
    if not original_anchors <= recovered_anchors:
        return source, original_tree, ()
    return parse_source, recovered_tree, masks


def _macro_function_masks(
    parser: Any,
    source: bytes,
) -> tuple[_MacroFunctionMask, ...]:
    lexical_source = _mask_c_comments_and_literals(source)
    masks: list[_MacroFunctionMask] = []
    occupied_until = 0
    for match in _IDENTIFIER_CALL.finditer(lexical_source):
        invocation_start = match.start()
        if invocation_start < occupied_until:
            continue
        open_parenthesis = lexical_source.find(b"(", invocation_start, match.end())
        invocation = _scan_invocation(lexical_source, open_parenthesis)
        if invocation is None:
            continue
        invocation_end, argument_spans = invocation
        body_start = _skip_whitespace(lexical_source, invocation_end)
        if body_start >= len(source) or lexical_source[body_start] != ord("{"):
            continue

        valid_signatures: list[tuple[int, _Span, _Span, _Span]] = []
        for argument_index in range(max(0, len(argument_spans) - 2)):
            declaration_argument = argument_spans[argument_index]
            name_argument = argument_spans[argument_index + 1]
            parameters_argument = argument_spans[argument_index + 2]
            declaration_span = _trim_whitespace(
                lexical_source,
                declaration_argument,
            )
            name_span = _single_identifier_span(lexical_source, name_argument)
            parameters_span = _parenthesized_span(
                lexical_source,
                parameters_argument,
            )
            if (
                declaration_span[0] >= declaration_span[1]
                or name_span is None
                or parameters_span is None
            ):
                continue
            if _probe_function_signature(
                parser,
                source[declaration_span[0] : declaration_span[1]],
                source[name_span[0] : name_span[1]],
                source[parameters_span[0] : parameters_span[1]],
            ):
                valid_signatures.append(
                    (
                        argument_index,
                        declaration_span,
                        name_span,
                        parameters_span,
                    )
                )
        if len(valid_signatures) != 1:
            continue
        argument_index, declaration_span, name_span, parameters_span = valid_signatures[
            0
        ]
        signature_indexes = {
            argument_index,
            argument_index + 1,
            argument_index + 2,
        }
        macro_name_match = _IDENTIFIER.match(lexical_source, invocation_start)
        if macro_name_match is None:
            continue
        annotation_arguments = tuple(
            _MacroAnnotationArgument(
                index=index,
                identifiers=tuple(
                    source[identifier.start() : identifier.end()].decode("ascii")
                    for identifier in _IDENTIFIER.finditer(
                        lexical_source,
                        span[0],
                        span[1],
                    )
                ),
            )
            for index, span in enumerate(argument_spans)
            if index not in signature_indexes
        )
        masks.append(
            _MacroFunctionMask(
                macro_name=source[
                    macro_name_match.start() : macro_name_match.end()
                ].decode("ascii"),
                argument_count=len(argument_spans),
                invocation_start=invocation_start,
                invocation_end=invocation_end,
                declaration_start=declaration_span[0],
                declaration_end=declaration_span[1],
                name_start=name_span[0],
                name_end=name_span[1],
                parameters_start=parameters_span[0],
                parameters_end=parameters_span[1],
                body_start=body_start,
                annotation_arguments=annotation_arguments,
            )
        )
        occupied_until = invocation_end
    return tuple(masks)


def _macro_function_definitions(
    tree: Any,
    source: bytes,
) -> tuple[_MacroFunctionDefinition, ...]:
    lexical_source = _mask_c_comments_and_literals(source)
    definitions: list[_MacroFunctionDefinition] = []
    for node in _walk_nodes(tree.root_node()):
        if node.kind() != "preproc_function_def":
            continue
        name_node = node.child_by_field_name("name")
        parameters_node = node.child_by_field_name("parameters")
        value_node = node.child_by_field_name("value")
        if name_node is None or parameters_node is None or value_node is None:
            continue
        parameters = tuple(
            source[child.start_byte() : child.end_byte()].decode("ascii")
            for child in _walk_nodes(parameters_node)
            if child.kind() == "identifier"
        )
        if not parameters or len(parameters) != len(set(parameters)):
            continue
        value_span = (value_node.start_byte(), value_node.end_byte())
        referenced_parameters = frozenset(
            parameter_index
            for parameter_index, parameter in enumerate(parameters)
            if any(
                match.group() == parameter.encode("ascii")
                for match in _IDENTIFIER.finditer(
                    lexical_source,
                    value_span[0],
                    value_span[1],
                )
            )
        )
        definitions.append(
            _MacroFunctionDefinition(
                name=source[name_node.start_byte() : name_node.end_byte()].decode(
                    "ascii"
                ),
                parameters=parameters,
                referenced_parameter_indexes=referenced_parameters,
                passthrough_parameter_index=_passthrough_parameter_index(
                    source,
                    value_span,
                    parameters,
                ),
            )
        )
    return tuple(definitions)


def _passthrough_parameter_index(
    source: bytes,
    value_span: _Span,
    parameters: tuple[str, ...],
) -> int | None:
    identifier_span = _single_identifier_span(source, value_span)
    if identifier_span is not None:
        identifier = source[identifier_span[0] : identifier_span[1]].decode("ascii")
        return parameters.index(identifier) if identifier in parameters else None

    start, end = _trim_whitespace(source, value_span)
    value = source[start:end]
    named_cast = re.fullmatch(
        rb"(?:static_cast|reinterpret_cast|const_cast)"
        rb"\s*<[^<>]+>\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
        value,
    )
    if named_cast is None:
        return None
    identifier = named_cast.group(1).decode("ascii")
    return parameters.index(identifier) if identifier in parameters else None


def _mask_c_comments_and_literals(source: bytes) -> bytes:
    masked = bytearray(source)
    index = 0
    while index < len(source):
        if source.startswith(b"//", index):
            end = source.find(b"\n", index + 2)
            end = len(source) if end < 0 else end
            _mask_non_newlines(masked, source, index, end)
            index = end
            continue
        if source.startswith(b"/*", index):
            closing = source.find(b"*/", index + 2)
            end = len(source) if closing < 0 else closing + 2
            _mask_non_newlines(masked, source, index, end)
            index = end
            continue
        if source[index] in {ord('"'), ord("'")}:
            quote = source[index]
            end = index + 1
            while end < len(source):
                if source[end] == ord("\\"):
                    end = min(len(source), end + 2)
                    continue
                end += 1
                if source[end - 1] == quote:
                    break
            _mask_non_newlines(masked, source, index, end)
            index = end
            continue
        index += 1
    return bytes(masked)


def _mask_non_newlines(
    target: bytearray,
    source: bytes,
    start: int,
    end: int,
) -> None:
    for index in range(start, end):
        if source[index] not in {ord("\n"), ord("\r")}:
            target[index] = ord(" ")


def _scan_invocation(
    source: bytes,
    open_parenthesis: int,
) -> tuple[int, tuple[_Span, ...]] | None:
    if open_parenthesis < 0 or source[open_parenthesis] != ord("("):
        return None
    parenthesis_depth = 1
    bracket_depth = 0
    brace_depth = 0
    argument_start = open_parenthesis + 1
    arguments: list[_Span] = []
    index = argument_start
    while index < len(source):
        value = source[index]
        if value == ord("("):
            parenthesis_depth += 1
        elif value == ord(")"):
            parenthesis_depth -= 1
            if parenthesis_depth == 0:
                arguments.append((argument_start, index))
                return index + 1, tuple(arguments)
        elif value == ord("["):
            bracket_depth += 1
        elif value == ord("]"):
            bracket_depth = max(0, bracket_depth - 1)
        elif value == ord("{"):
            brace_depth += 1
        elif value == ord("}"):
            brace_depth = max(0, brace_depth - 1)
        elif (
            value == ord(",")
            and parenthesis_depth == 1
            and bracket_depth == 0
            and brace_depth == 0
        ):
            arguments.append((argument_start, index))
            argument_start = index + 1
        index += 1
    return None


def _single_identifier_span(
    source: bytes,
    span: _Span,
) -> _Span | None:
    start, end = _trim_whitespace(source, span)
    while start < end and source[start] == ord("("):
        closing = _matching_parenthesis(source, start)
        if closing != end - 1:
            break
        start, end = _trim_whitespace(source, (start + 1, closing))
    match = _IDENTIFIER.fullmatch(source[start:end])
    return (start, end) if match is not None else None


def _parenthesized_span(
    source: bytes,
    span: _Span,
) -> _Span | None:
    start, end = _trim_whitespace(source, span)
    if start >= end or source[start] != ord("("):
        return None
    closing = _matching_parenthesis(source, start)
    return (start, end) if closing == end - 1 else None


def _matching_parenthesis(source: bytes, start: int) -> int | None:
    depth = 0
    for index in range(start, len(source)):
        if source[index] == ord("("):
            depth += 1
        elif source[index] == ord(")"):
            depth -= 1
            if depth == 0:
                return index
    return None


def _trim_whitespace(source: bytes, span: _Span) -> _Span:
    start, end = span
    while start < end and chr(source[start]).isspace():
        start += 1
    while end > start and chr(source[end - 1]).isspace():
        end -= 1
    return start, end


def _skip_whitespace(source: bytes, start: int) -> int:
    while start < len(source) and chr(source[start]).isspace():
        start += 1
    return start


def _probe_function_signature(
    parser: Any,
    declaration: bytes,
    name: bytes,
    parameters: bytes,
) -> bool:
    probe = declaration + b" " + name + b" " + parameters + b" {}"
    root = parser.parse_bytes(probe).root_node()
    if root.has_error() or root.child_count() != 1:
        return False
    function = root.child(0)
    if function is None or function.kind() != "function_definition":
        return False
    declarator = function.child_by_field_name("declarator")
    body = function.child_by_field_name("body")
    if declarator is None or body is None:
        return False
    return any(
        child.kind() == "identifier"
        and probe[child.start_byte() : child.end_byte()] == name
        for child in _walk_nodes(declarator)
    )


def _render_macro_function_masks(
    source: bytes,
    masks: tuple[_MacroFunctionMask, ...],
) -> bytes:
    rendered = bytearray(source)
    for mask in masks:
        _mask_non_newlines(
            rendered,
            source,
            mask.invocation_start,
            mask.invocation_end,
        )
        rendered[mask.declaration_start : mask.declaration_end] = source[
            mask.declaration_start : mask.declaration_end
        ]
        rendered[mask.name_start : mask.name_end] = source[
            mask.name_start : mask.name_end
        ]
        rendered[mask.parameters_start : mask.parameters_end] = source[
            mask.parameters_start : mask.parameters_end
        ]
    return bytes(rendered)


def _function_anchors(tree: Any, source: bytes) -> set[tuple[int, int, int]]:
    anchors: set[tuple[int, int, int]] = set()
    for node in _walk_nodes(tree.root_node()):
        if node.kind() != "function_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        body = node.child_by_field_name("body")
        if declarator is None or body is None:
            continue
        name = next(
            (
                child
                for child in _walk_nodes(declarator)
                if child.kind() == "identifier"
            ),
            None,
        )
        if name is None or not _IDENTIFIER.fullmatch(
            source[name.start_byte() : name.end_byte()]
        ):
            continue
        anchors.add((name.start_byte(), name.end_byte(), body.start_byte()))
    return anchors


def _walk_nodes(root: Any):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(
            reversed(
                [
                    child
                    for index in range(node.child_count())
                    if (child := node.child(index)) is not None
                ]
            )
        )
