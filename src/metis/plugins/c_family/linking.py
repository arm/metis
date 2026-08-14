# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass

from metis.engine.codegraph import CallKind
from metis.engine.codegraph import CallSite
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import FunctionNode
from metis.engine.codegraph import SymbolReference
from metis.engine.nodes.codegraph.annotations import (
    GLOBAL_INITIALIZER_ENTRYPOINT_REASON,
)

from .ast import ANONYMOUS_NAMESPACE_SCOPE
from .ast import CFamilyCallSite
from .ast import CFamilyFunctionSyntax
from .runtime import _MacroFunctionMask


@dataclass
class ValueBinding:
    name: str
    declaration_byte: int
    scope_start_byte: int
    scope_end_byte: int
    targets: list[SymbolReference] | None = None


@dataclass
class ParsedFunction:
    node: FunctionNode
    syntax: CFamilyFunctionSyntax
    calls: tuple[CFamilyCallSite, ...]
    value_bindings: tuple[ValueBinding, ...]
    macro_function_mask: _MacroFunctionMask | None = None


def _visible_value_binding(
    bindings: tuple[ValueBinding, ...],
    *,
    name: str,
    at_byte: int,
) -> ValueBinding | None:
    visible = [
        binding
        for binding in bindings
        if binding.name == name
        and binding.declaration_byte <= at_byte
        and binding.scope_start_byte <= at_byte <= binding.scope_end_byte
    ]
    if not visible:
        return None
    return max(visible, key=lambda binding: binding.declaration_byte)


def _resolve_calls(
    graph: CodeGraph,
    functions: list[ParsedFunction],
    declarations: list[CFamilyFunctionSyntax],
    global_languages: dict[str, str],
    global_scopes: dict[str, tuple[str, ...]],
    value_declarations: dict[tuple[str, str], list[int]],
) -> None:
    definitions_by_name: dict[str, list[ParsedFunction]] = {}
    definitions_by_qualified_name: dict[str, list[ParsedFunction]] = {}
    for function in functions:
        definitions_by_name.setdefault(function.node.name, []).append(function)
        definitions_by_qualified_name.setdefault(
            function.syntax.qualified_name, []
        ).append(function)
        if ANONYMOUS_NAMESPACE_SCOPE in function.syntax.lexical_scope:
            visible_name = "::".join(
                part
                for part in function.syntax.qualified_name.split("::")
                if part != ANONYMOUS_NAMESPACE_SCOPE
            )
            definitions_by_qualified_name.setdefault(visible_name, []).append(function)
    declared_minimums: dict[tuple[str, str], int] = {}
    for declaration in declarations:
        key = (declaration.qualified_name, declaration.signature_suffix)
        current = declared_minimums.get(key, declaration.minimum_argument_count)
        declared_minimums[key] = min(current, declaration.minimum_argument_count)

    for caller in functions:
        resolved: list[str] = []
        call_sites: list[CallSite] = []
        for call in caller.calls:
            kind: CallKind
            pointer_targets = _pointer_targets_for_call(caller, call)
            if pointer_targets is not None:
                candidates = [
                    candidate
                    for reference in pointer_targets
                    for candidate in _reference_candidates(
                        reference,
                        definitions_by_name,
                        definitions_by_qualified_name,
                        value_declarations,
                        file_path=caller.node.file_path,
                        language=caller.node.language,
                        lexical_scope=caller.syntax.lexical_scope,
                        value_bindings=caller.value_bindings,
                    )
                ]
                kind = "indirect"
            else:
                candidates = (
                    _call_candidates(
                        call,
                        caller,
                        definitions_by_name,
                        definitions_by_qualified_name,
                        declared_minimums,
                    )
                    if caller.node.language == "cpp"
                    else _c_call_candidates(
                        call,
                        caller,
                        definitions_by_name,
                        value_declarations,
                    )
                )
                kind = call.kind
            target_ids = tuple(
                dict.fromkeys(candidate.node.unique_name for candidate in candidates)
            )
            call_sites.append(
                CallSite(
                    symbol=call.precise_symbol,
                    line=call.line,
                    argument_count=call.argument_count,
                    kind=kind,
                    start_byte=call.start_byte,
                    end_byte=call.end_byte,
                    qualified_name=call.qualified_name,
                    generic_qualified_name=call.generic_qualified_name,
                    receiver=call.receiver,
                    target_ids=target_ids,
                    arguments=call.arguments,
                    conditions=call.conditions,
                    must_conditions=call.must_conditions,
                    result=call.result,
                )
            )
            resolved.extend(target_ids)
        caller.node.call_sites = call_sites
        caller.node.references = [
            reference.with_targets(
                tuple(
                    dict.fromkeys(
                        candidate.node.unique_name
                        for candidate in _reference_candidates(
                            reference,
                            definitions_by_name,
                            definitions_by_qualified_name,
                            value_declarations,
                            file_path=caller.node.file_path,
                            language=caller.node.language,
                            lexical_scope=caller.syntax.lexical_scope,
                            value_bindings=caller.value_bindings,
                        )
                    )
                )
            )
            for reference in caller.node.references
        ]
        caller.node.resolved_calls = list(dict.fromkeys(resolved))

    for construct in graph.globals.values():
        construct.references = [
            reference.with_targets(
                tuple(
                    dict.fromkeys(
                        candidate.node.unique_name
                        for candidate in _reference_candidates(
                            reference,
                            definitions_by_name,
                            definitions_by_qualified_name,
                            value_declarations,
                            file_path=construct.file_path,
                            language=global_languages[construct.unique_name],
                            lexical_scope=global_scopes[construct.unique_name],
                            value_bindings=(),
                        )
                    )
                )
            )
            for reference in construct.references
        ]
        for reference in construct.references:
            for target_id in reference.target_ids:
                target = graph.get_node(target_id)
                if target is None:
                    continue
                target.is_public_entrypoint = True
                target.entrypoint_reason = GLOBAL_INITIALIZER_ENTRYPOINT_REASON


def _pointer_targets_for_call(
    caller: ParsedFunction,
    call: CFamilyCallSite,
) -> tuple[SymbolReference, ...] | None:
    if call.receiver:
        return None
    binding = _visible_value_binding(
        caller.value_bindings,
        name=call.precise_symbol,
        at_byte=call.start_byte,
    )
    if binding is None:
        return None
    return tuple(
        target
        for target in binding.targets or ()
        if target.start_byte < call.start_byte
    )


def _reference_candidates(
    reference: SymbolReference,
    definitions_by_name: dict[str, list[ParsedFunction]],
    definitions_by_qualified_name: dict[str, list[ParsedFunction]],
    value_declarations: dict[tuple[str, str], list[int]],
    *,
    file_path: str,
    language: str,
    lexical_scope: tuple[str, ...],
    value_bindings: tuple[ValueBinding, ...],
) -> list[ParsedFunction]:
    symbol = reference.symbol.removeprefix("::")
    is_qualified = reference.symbol.startswith("::") or "::" in symbol
    if not is_qualified and _visible_value_binding(
        value_bindings,
        name=symbol,
        at_byte=reference.start_byte,
    ):
        return []
    candidates: list[ParsedFunction] = []
    if language == "cpp":
        candidate_names = [symbol]
        if not reference.symbol.startswith("::"):
            candidate_names = [
                "::".join((*lexical_scope[:depth], symbol))
                for depth in range(len(lexical_scope), -1, -1)
            ]
        for candidate_name in candidate_names:
            if _has_visible_value_declaration(
                value_declarations,
                file_path=file_path,
                qualified_name=candidate_name,
                at_byte=reference.start_byte,
            ):
                return []
            candidates = definitions_by_qualified_name.get(candidate_name, [])
            if candidates:
                break
    elif _has_visible_value_declaration(
        value_declarations,
        file_path=file_path,
        qualified_name=symbol,
        at_byte=reference.start_byte,
    ):
        return []
    if not candidates and not is_qualified:
        candidates = definitions_by_name.get(symbol.rpartition("::")[2], [])
    candidates = [
        candidate
        for candidate in candidates
        if candidate.node.language == language
        and (
            not candidate.node.has_internal_linkage
            or candidate.node.file_path == file_path
        )
    ]
    if not is_qualified:
        candidates = _visible_anonymous_namespace_candidates(
            candidates,
            lexical_scope,
        )
    return candidates


def _c_call_candidates(
    call: CFamilyCallSite,
    caller: ParsedFunction,
    definitions_by_name: dict[str, list[ParsedFunction]],
    value_declarations: dict[tuple[str, str], list[int]],
) -> list[ParsedFunction]:
    if call.kind != "direct":
        return []
    if _has_visible_value_declaration(
        value_declarations,
        file_path=caller.node.file_path,
        qualified_name=call.precise_symbol,
        at_byte=call.start_byte,
    ):
        return []
    candidates = [
        candidate
        for candidate in definitions_by_name.get(call.precise_symbol, [])
        if candidate.node.language == "c"
        and (
            not candidate.node.has_internal_linkage
            or candidate.node.file_path == caller.node.file_path
        )
    ]
    same_file = [
        candidate
        for candidate in candidates
        if candidate.node.file_path == caller.node.file_path
    ]
    return same_file or candidates


def _has_visible_value_declaration(
    value_declarations: dict[tuple[str, str], list[int]],
    *,
    file_path: str,
    qualified_name: str,
    at_byte: int,
) -> bool:
    return any(
        declaration_byte <= at_byte
        for declaration_byte in value_declarations.get(
            (file_path, qualified_name),
            (),
        )
    )


def _visible_anonymous_namespace_candidates(
    candidates: list[ParsedFunction],
    lexical_scope: tuple[str, ...],
) -> list[ParsedFunction]:
    visible: list[ParsedFunction] = []
    for candidate in candidates:
        scope = candidate.syntax.lexical_scope
        if ANONYMOUS_NAMESPACE_SCOPE not in scope:
            visible.append(candidate)
            continue
        enclosing_scope = scope[: scope.index(ANONYMOUS_NAMESPACE_SCOPE)]
        if lexical_scope[: len(enclosing_scope)] == enclosing_scope:
            visible.append(candidate)
    return visible


def _call_candidates(
    call: CFamilyCallSite,
    caller: ParsedFunction,
    definitions_by_name: dict[str, list[ParsedFunction]],
    definitions_by_qualified_name: dict[str, list[ParsedFunction]],
    declared_minimums: dict[tuple[str, str], int],
) -> list[ParsedFunction]:
    candidates: list[ParsedFunction] = []
    if call.qualified_name:
        qualified_names = tuple(
            dict.fromkeys((call.qualified_name, call.generic_qualified_name))
        )
        for qualified_name in qualified_names:
            normalized_name = qualified_name.removeprefix("::")
            candidate_names = [normalized_name]
            if not qualified_name.startswith("::"):
                candidate_names = [
                    "::".join((*caller.syntax.lexical_scope[:depth], normalized_name))
                    for depth in range(len(caller.syntax.lexical_scope), -1, -1)
                ]
            for candidate_name in candidate_names:
                candidates = definitions_by_qualified_name.get(candidate_name, [])
                if candidates:
                    break
            if candidates:
                break
    elif call.receiver == "this":
        member_scope = caller.syntax.qualified_name.rpartition("::")[0]
        candidates = definitions_by_qualified_name.get(
            f"{member_scope}::{call.symbol}", []
        )
    elif call.receiver:
        return []
    elif not call.receiver:
        for depth in range(len(caller.syntax.lexical_scope), -1, -1):
            candidate_name = "::".join(
                (*caller.syntax.lexical_scope[:depth], call.symbol)
            )
            candidates = definitions_by_qualified_name.get(candidate_name, [])
            if candidates:
                break

    if not candidates and call.qualified_name:
        return []
    if not candidates:
        candidates = list(definitions_by_name.get(call.symbol, []))

    candidates = [
        candidate
        for candidate in candidates
        if not candidate.node.has_internal_linkage
        or candidate.node.file_path == caller.node.file_path
    ]
    if not call.qualified_name:
        candidates = _visible_anonymous_namespace_candidates(
            candidates,
            caller.syntax.lexical_scope,
        )
        same_file = [
            candidate
            for candidate in candidates
            if candidate.node.file_path == caller.node.file_path
        ]
        if same_file:
            candidates = same_file

    return [
        candidate
        for candidate in candidates
        if declared_minimums.get(
            (candidate.syntax.qualified_name, candidate.syntax.signature_suffix),
            candidate.syntax.minimum_argument_count,
        )
        <= call.argument_count
        and (
            candidate.syntax.maximum_argument_count is None
            or call.argument_count <= candidate.syntax.maximum_argument_count
        )
    ]
