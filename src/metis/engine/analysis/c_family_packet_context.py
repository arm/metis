# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any

from .c_family_analyzer_common import (
    _identifier_from_node,
    _node_end_line,
    _node_line,
    _node_text,
)
from .c_family_helpers import parse_includes_from_text, resolve_include_path
from .static_inventory import StaticInventory
from .static_xref import find_symbol_definitions
from .treesitter_runtime import TreeSitterRuntime

C_FAMILY_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
C_FAMILY_GUARD_TERMS = (
    "if",
    "check",
    "validate",
    "sanitize",
    "bound",
    "limit",
    "size",
    "len",
    "auth",
    "lock",
    "null",
)
C_FAMILY_CALLEE_PRIORITY_TERMS = (
    "check",
    "validate",
    "sanitize",
    "copy",
    "alloc",
    "free",
    "lock",
    "unlock",
    "auth",
    "verify",
)

_TYPEDEF_ALIAS_RE = re.compile(r"\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", re.S)
_GENERIC_TYPEDEF_ALIAS_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$")
_DIRECT_ASSIGN_RE = re.compile(
    r"^\s*&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*$",
)
_MACRO_DEFINE_RE = re.compile(
    r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)(\(([^)]*)\))?\s*(.*)$"
)
_MACRO_TOKEN_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


@dataclass(frozen=True)
class CFamilyTypeDecl:
    name: str
    kind: str
    text: str
    line_start: int
    line_end: int
    function_pointer_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class CFamilyAliasBinding:
    symbol: str
    target_symbol: str
    scope_key: str
    line: int
    evidence_kind: str
    evidence_text: str


@dataclass(frozen=True)
class CFamilyFieldBinding:
    base_symbol: str
    field_name: str
    target_symbol: str
    scope_key: str
    line: int
    evidence_kind: str
    evidence_text: str


@dataclass(frozen=True)
class CFamilyIndirectCall:
    expression: str
    line: int
    callsite_text: str
    scope_key: str
    base_symbol: str = ""
    member_name: str = ""
    kind: str = ""


@dataclass(frozen=True)
class CFamilyVarType:
    symbol: str
    type_name: str
    scope_key: str
    line: int


@dataclass(frozen=True)
class CFamilyMacroDef:
    name: str
    body: str
    file_path: str
    line: int
    is_function_like: bool = False
    parameters: tuple[str, ...] = ()


@dataclass
class CFamilyFileContext:
    type_decls: list[CFamilyTypeDecl] = field(default_factory=list)
    alias_bindings: list[CFamilyAliasBinding] = field(default_factory=list)
    field_bindings: list[CFamilyFieldBinding] = field(default_factory=list)
    indirect_calls: list[CFamilyIndirectCall] = field(default_factory=list)
    variable_types: list[CFamilyVarType] = field(default_factory=list)
    function_pointer_variables: set[tuple[str, str]] = field(default_factory=set)
    function_pointer_typedefs: set[str] = field(default_factory=set)
    macro_definitions: list[CFamilyMacroDef] = field(default_factory=list)


_RUNTIMES: dict[str, TreeSitterRuntime] = {}
GLOBAL_SCOPE = "__global__"


def is_c_family_file(file_path: str) -> bool:
    return Path(file_path).suffix.lower() in C_FAMILY_EXTENSIONS


def c_family_neighbor_signal_score(
    unit: Any,
    neighbor: Any,
    *,
    relation: str,
    codebase_path: str | Path,
    excerpt_for_unit,
) -> int:
    if not is_c_family_file(str(_unit_get(unit, "file_path", "") or "")):
        return 0
    neighbor_name = str(_unit_get(neighbor, "name", "") or "").lower()
    neighbor_refs = " ".join(
        str(ref).lower() for ref in (_unit_get(neighbor, "references", []) or [])
    )
    neighbor_calls = " ".join(
        str(call).lower() for call in (_unit_get(neighbor, "calls", []) or [])
    )
    neighbor_source = excerpt_for_unit(
        neighbor,
        codebase_path=codebase_path,
        max_lines=30,
    ).lower()
    text = f"{neighbor_name} {neighbor_refs} {neighbor_calls} {neighbor_source}"
    unit_refs = {
        str(ref).lower()
        for ref in (_unit_get(unit, "references", []) or [])
        if str(ref).strip()
    }
    shared_refs = sum(1 for ref in unit_refs if ref and ref in text)
    term_hits = 0
    if relation == "caller":
        term_hits += sum(1 for term in C_FAMILY_GUARD_TERMS if term in text)
        if "if (" in text or "if(" in text:
            term_hits += 3
        if "return -1" in text or "return false" in text:
            term_hits += 2
    else:
        term_hits += sum(1 for term in C_FAMILY_CALLEE_PRIORITY_TERMS if term in text)
        unit_calls = {
            str(call).lower()
            for call in (_unit_get(unit, "calls", []) or [])
            if str(call).strip()
        }
        term_hits += sum(1 for call in unit_calls if call and call in text)
    return (shared_refs * 3) + term_hits


def build_c_family_type_context(
    unit: Any,
    *,
    codebase_path: str | Path,
    limit: int,
) -> list[str]:
    context = _build_context_for_unit(unit, codebase_path=codebase_path)
    if context is None:
        return []
    unit_calls = _unit_indirect_calls(context, unit)
    references = {
        str(ref)
        for ref in (_unit_get(unit, "references", []) or [])
        if str(ref).strip()
    }
    wanted_fields = {
        call.member_name for call in unit_calls if getattr(call, "member_name", "")
    }
    blocks: list[str] = []
    seen: set[str] = set()
    for decl in context.type_decls:
        if decl.name in seen:
            continue
        if decl.name not in references and not wanted_fields.intersection(
            set(decl.function_pointer_fields)
        ):
            continue
        seen.add(decl.name)
        blocks.append(f"- {decl.kind}: {decl.name}")
        blocks.extend(_indent_block(decl.text, prefix="    "))
        if len(seen) >= limit:
            break
    return blocks


def build_c_family_indirect_call_context(
    inventory: dict[str, Any] | StaticInventory,
    unit: Any,
    *,
    codebase_path: str | Path,
    limit: int,
) -> list[str]:
    context = _build_context_for_unit(unit, codebase_path=codebase_path)
    if context is None:
        return []

    unit_id = str(_unit_get(unit, "unit_id", "") or "")
    blocks: list[str] = []
    for call in _unit_indirect_calls(context, unit)[:limit]:
        resolution = _resolve_indirect_call(
            inventory,
            context,
            call,
            caller_unit_id=unit_id,
        )
        blocks.append(f"- expression: {call.expression}(...)")
        blocks.append(f"  status: {resolution['status']}")
        if call.callsite_text:
            blocks.append(f"  callsite: {call.callsite_text.strip()}")
        if resolution["resolved_target"]:
            blocks.append(f"  resolved_target: {resolution['resolved_target']}")
        else:
            blocks.append(f"  unresolved_reason: {resolution['reason']}")
        if resolution["resolution_kind"]:
            blocks.append(f"  resolution_kind: {resolution['resolution_kind']}")
        if resolution["supporting_evidence"]:
            blocks.append("  supporting_evidence:")
            blocks.extend(
                _indent_block(resolution["supporting_evidence"], prefix="    ")
            )
        if resolution["type_decl"]:
            blocks.append("  supporting_type:")
            blocks.extend(_indent_block(resolution["type_decl"], prefix="    "))
    return blocks


def build_c_family_macro_expansion_context(
    unit: Any,
    *,
    codebase_path: str | Path,
    limit: int,
) -> list[str]:
    context = _build_context_for_unit(unit, codebase_path=codebase_path)
    if context is None:
        return []
    references = {
        str(ref)
        for ref in (_unit_get(unit, "references", []) or [])
        if str(ref).strip()
    }
    source_text = _unit_source_text(unit, codebase_path=codebase_path)
    macro_names: list[str] = []
    for macro in context.macro_definitions:
        if macro.name in references or macro.name in source_text:
            if macro.name not in macro_names:
                macro_names.append(macro.name)
    blocks: list[str] = []
    for macro_name in macro_names[:limit]:
        chain = _expand_macro_chain(context, macro_name)
        if not chain:
            continue
        top = chain[0]
        blocks.append(f"- macro: {macro_name}")
        blocks.append(f"  defined_at: {top.file_path}:{top.line}")
        blocks.extend(_indent_block(_macro_signature(top), prefix="    "))
        if len(chain) > 1:
            blocks.append(
                f"  expansion_chain: {' -> '.join(item.name for item in chain)}"
            )
        terminal = _macro_terminal_text(chain[-1])
        if terminal:
            blocks.append(f"  terminal: {terminal}")
    return blocks


def _unit_indirect_calls(
    context: CFamilyFileContext,
    unit: Any,
) -> list[CFamilyIndirectCall]:
    start_line = int(_unit_get(unit, "start_line", 0) or 0)
    end_line = int(_unit_get(unit, "end_line", 0) or 0)
    if start_line <= 0 or end_line < start_line:
        return list(context.indirect_calls)
    return [
        call for call in context.indirect_calls if start_line <= call.line <= end_line
    ]


def _build_context_for_unit(
    unit: Any,
    *,
    codebase_path: str | Path,
) -> CFamilyFileContext | None:
    file_path = str(_unit_get(unit, "file_path", "") or "")
    if not is_c_family_file(file_path):
        return None
    language = _language_for_file(file_path)
    runtime = _RUNTIMES.get(language)
    if runtime is None:
        runtime = TreeSitterRuntime(language)
        _RUNTIMES[language] = runtime
    if not runtime.is_available:
        return None
    try:
        parsed = runtime.parse_file(str(codebase_path), file_path)
    except Exception:
        return None
    source = bytes(parsed.text, "utf-8")
    root = parsed.tree.root_node
    context = _collect_file_context(root, source)
    context.macro_definitions = _collect_macro_definitions(
        codebase_path=Path(codebase_path).resolve(),
        file_path=file_path,
        source_text=parsed.text,
        depth=2,
    )
    return context


def _collect_file_context(root: Any, source: bytes) -> CFamilyFileContext:
    out = CFamilyFileContext()

    def walk(node, scope_key: str):
        node_type = str(getattr(node, "type", "") or "")
        next_scope = scope_key
        if node_type in {"function_definition", "method_definition"}:
            next_scope = _scope_key_for_function(node, source)
        if node_type in {"type_definition", "struct_specifier", "class_specifier"}:
            decl = _type_decl_from_node(node, source)
            if decl is not None and decl not in out.type_decls:
                out.type_decls.append(decl)
        if node_type == "type_definition":
            typedef_name = _function_pointer_typedef_name(node, source)
            if typedef_name:
                out.function_pointer_typedefs.add(typedef_name)
        if node_type == "declaration":
            _collect_declaration_info(node, source, out, scope_key=next_scope)
        if node_type == "assignment_expression":
            _collect_assignment_info(node, source, out, scope_key=next_scope)
        if node_type == "call_expression":
            call = _indirect_call_from_node(node, source, out, scope_key=next_scope)
            if call is not None:
                out.indirect_calls.append(call)
        for child in getattr(node, "children", []) or []:
            walk(child, next_scope)

    walk(root, GLOBAL_SCOPE)
    out.type_decls.sort(key=lambda item: (item.line_start, item.name.lower()))
    out.alias_bindings.sort(key=lambda item: (item.line, item.symbol))
    out.field_bindings.sort(
        key=lambda item: (item.line, item.base_symbol, item.field_name)
    )
    out.indirect_calls.sort(key=lambda item: (item.line, item.expression))
    out.variable_types.sort(key=lambda item: (item.line, item.symbol))
    return out


def _type_decl_from_node(node: Any, source: bytes) -> CFamilyTypeDecl | None:
    node_type = str(getattr(node, "type", "") or "")
    if node_type == "struct_specifier":
        name = _identifier_from_node(_child_by_field(node, "name"), source) or ""
        fields = tuple(_function_pointer_fields(node, source))
        if not name or not fields:
            return None
        return CFamilyTypeDecl(
            name=name,
            kind="struct",
            text=_node_text(node, source).strip(),
            line_start=_node_line(node),
            line_end=_node_end_line(node),
            function_pointer_fields=fields,
        )
    if node_type == "type_definition":
        text = _node_text(node, source).strip()
        if "struct" not in text:
            return None
        name = _typedef_alias_name(text)
        fields = tuple(_function_pointer_fields(node, source))
        if not name or not fields:
            return None
        return CFamilyTypeDecl(
            name=name,
            kind="typedef",
            text=text,
            line_start=_node_line(node),
            line_end=_node_end_line(node),
            function_pointer_fields=fields,
        )
    return None


def _function_pointer_typedef_name(node: Any, source: bytes) -> str:
    if str(getattr(node, "type", "") or "") != "type_definition":
        return ""
    text = _node_text(node, source).strip()
    if "(*)" in text:
        return _typedef_function_pointer_alias(text)
    if "(*" in text:
        return _typedef_function_pointer_alias(text)
    return ""


def _fallback_declared_names_from_text(
    decl_text: str,
    *,
    type_name: str,
) -> list[tuple[str, str]]:
    pattern = re.compile(
        rf"\b{re.escape(type_name)}\b\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*([^;,]+))?"
    )
    out: list[tuple[str, str]] = []
    for match in pattern.finditer(decl_text):
        name = str(match.group(1) or "").strip()
        init = str(match.group(2) or "").strip()
        if not name:
            continue
        direct = ""
        if init:
            tokens = _MACRO_TOKEN_RE.findall(init)
            if tokens:
                direct = tokens[0]
        out.append((name, direct))
    return out


def _collect_declaration_info(
    node: Any,
    source: bytes,
    out: CFamilyFileContext,
    *,
    scope_key: str,
) -> None:
    type_name = _type_name_from_declaration(node, source)
    decl_text = _node_text(node, source)
    if not type_name:
        for typedef_name in sorted(out.function_pointer_typedefs):
            if re.search(rf"\b{re.escape(typedef_name)}\b", decl_text):
                type_name = typedef_name
                break
    function_pointer_type = _declaration_contains_function_pointer(node)
    if type_name and type_name in out.function_pointer_typedefs:
        function_pointer_type = True
    seen_names: set[str] = set()
    for child in getattr(node, "children", []) or []:
        child_type = str(getattr(child, "type", "") or "")
        if child_type != "init_declarator":
            if child_type in {
                "pointer_declarator",
                "function_declarator",
                "identifier",
            }:
                name = _identifier_from_node(child, source)
                if name and type_name:
                    seen_names.add(name)
                    out.variable_types.append(
                        CFamilyVarType(
                            symbol=name,
                            type_name=type_name,
                            scope_key=scope_key,
                            line=_node_line(node),
                        )
                    )
                if name and function_pointer_type:
                    out.function_pointer_variables.add((scope_key, name))
            continue
        declarator = _child_by_field(
            child, "declarator"
        ) or _first_non_initializer_child(child)
        initializer = _child_by_field(child, "value") or _find_initializer_node(child)
        name = _identifier_from_node(declarator, source)
        if not name:
            continue
        seen_names.add(name)
        if type_name:
            out.variable_types.append(
                CFamilyVarType(
                    symbol=name,
                    type_name=type_name,
                    scope_key=scope_key,
                    line=_node_line(child),
                )
            )
    if type_name:
        for fallback_name, fallback_init in _fallback_declared_names_from_text(
            decl_text,
            type_name=type_name,
        ):
            if fallback_name in seen_names:
                continue
            out.variable_types.append(
                CFamilyVarType(
                    symbol=fallback_name,
                    type_name=type_name,
                    scope_key=scope_key,
                    line=_node_line(node),
                )
            )
            if function_pointer_type:
                out.function_pointer_variables.add((scope_key, fallback_name))
            if fallback_init:
                out.alias_bindings.append(
                    CFamilyAliasBinding(
                        symbol=fallback_name,
                        target_symbol=fallback_init,
                        scope_key=scope_key,
                        line=_node_line(node),
                        evidence_kind="declaration_text_alias",
                        evidence_text=decl_text.strip(),
                    )
                )
        if _contains_function_pointer_declarator(declarator):
            out.function_pointer_variables.add((scope_key, name))
        alias_target = _extract_direct_symbol(initializer, source)
        if alias_target:
            out.alias_bindings.append(
                CFamilyAliasBinding(
                    symbol=name,
                    target_symbol=alias_target,
                    scope_key=scope_key,
                    line=_node_line(child),
                    evidence_kind="initializer_alias",
                    evidence_text=_node_text(child, source).strip(),
                )
            )
        elif name:
            alias_target = _resolve_member_target_from_node(
                initializer,
                source,
                out,
                scope_key=scope_key,
                line=_node_line(child),
            )
            if alias_target:
                out.alias_bindings.append(
                    CFamilyAliasBinding(
                        symbol=name,
                        target_symbol=alias_target,
                        scope_key=scope_key,
                        line=_node_line(child),
                        evidence_kind="initializer_member_alias",
                        evidence_text=_node_text(child, source).strip(),
                    )
                )
        for field_name, target_symbol in _extract_designated_bindings(
            initializer, source
        ):
            out.field_bindings.append(
                CFamilyFieldBinding(
                    base_symbol=name,
                    field_name=field_name,
                    target_symbol=target_symbol,
                    scope_key=scope_key,
                    line=_node_line(child),
                    evidence_kind="initializer_field_binding",
                    evidence_text=_node_text(child, source).strip(),
                )
            )


def _collect_assignment_info(
    node: Any,
    source: bytes,
    out: CFamilyFileContext,
    *,
    scope_key: str,
) -> None:
    left = _child_by_field(node, "left")
    right = _child_by_field(node, "right")
    if left is None or right is None:
        children = list(getattr(node, "children", []) or [])
        if len(children) >= 3:
            left = children[0]
            right = children[-1]
    if left is None or right is None:
        return

    base_symbol, field_name = _member_access_parts(left, source)
    if base_symbol and field_name:
        target_symbol = _extract_direct_symbol(right, source)
        if target_symbol:
            out.field_bindings.append(
                CFamilyFieldBinding(
                    base_symbol=base_symbol,
                    field_name=field_name,
                    target_symbol=target_symbol,
                    scope_key=scope_key,
                    line=_node_line(node),
                    evidence_kind="assignment_field_binding",
                    evidence_text=_node_text(node, source).strip(),
                )
            )
        return

    symbol = _identifier_from_node(left, source)
    target_symbol = _extract_direct_symbol(right, source)
    if symbol and target_symbol:
        out.alias_bindings.append(
            CFamilyAliasBinding(
                symbol=symbol,
                target_symbol=target_symbol,
                scope_key=scope_key,
                line=_node_line(node),
                evidence_kind="assignment_alias",
                evidence_text=_node_text(node, source).strip(),
            )
        )
        return
    if symbol:
        target_symbol = _resolve_member_target_from_node(
            right,
            source,
            out,
            scope_key=scope_key,
            line=_node_line(node),
        )
        if target_symbol:
            out.alias_bindings.append(
                CFamilyAliasBinding(
                    symbol=symbol,
                    target_symbol=target_symbol,
                    scope_key=scope_key,
                    line=_node_line(node),
                    evidence_kind="assignment_member_alias",
                    evidence_text=_node_text(node, source).strip(),
                )
            )


def _indirect_call_from_node(
    node: Any,
    source: bytes,
    context: CFamilyFileContext,
    *,
    scope_key: str,
) -> CFamilyIndirectCall | None:
    function_node = _child_by_field(node, "function")
    if function_node is None:
        children = list(getattr(node, "children", []) or [])
        function_node = children[0] if children else None
    if function_node is None:
        return None

    function_type = str(getattr(function_node, "type", "") or "")
    expression = _node_text(function_node, source).strip()
    if not expression:
        return None

    base_symbol = ""
    member_name = ""
    kind = ""
    if function_type in {"field_expression", "pointer_expression"}:
        base_symbol, member_name = _member_access_parts(function_node, source)
        if not base_symbol or not member_name:
            return None
        kind = "member_dispatch"
    elif function_type == "identifier":
        symbol = _identifier_from_node(function_node, source)
        if not _is_function_pointer_variable(
            context, symbol, scope_key
        ) and not _has_local_alias_binding(context, symbol, scope_key):
            return None
        base_symbol = symbol
        kind = "function_pointer_variable"
    elif "->" in expression or "." in expression:
        base_symbol, member_name = _member_access_parts(function_node, source)
        if not base_symbol or not member_name:
            return None
        kind = "member_dispatch"
    else:
        symbol = _identifier_from_node(function_node, source)
        if _is_function_pointer_variable(
            context, symbol, scope_key
        ) or _has_local_alias_binding(context, symbol, scope_key):
            base_symbol = symbol
            kind = "function_pointer_variable"
        else:
            return None

    return CFamilyIndirectCall(
        expression=expression,
        line=_node_line(node),
        callsite_text=_node_text(node, source).strip(),
        scope_key=scope_key,
        base_symbol=base_symbol,
        member_name=member_name,
        kind=kind,
    )


def _resolve_indirect_call(
    inventory: dict[str, Any] | StaticInventory,
    context: CFamilyFileContext,
    call: CFamilyIndirectCall,
    *,
    caller_unit_id: str,
) -> dict[str, str]:
    if call.kind == "function_pointer_variable":
        target, evidence_kind, evidence_text = _resolve_alias_target(
            context,
            symbol=call.base_symbol,
            scope_key=call.scope_key,
            line=call.line,
        )
        if target and _resolved_definition_exists(
            inventory,
            target,
            caller_unit_id=caller_unit_id,
        ):
            return {
                "status": "resolved",
                "resolved_target": target,
                "reason": "",
                "resolution_kind": evidence_kind,
                "supporting_evidence": evidence_text,
                "type_decl": "",
            }
        return {
            "status": "unresolved",
            "resolved_target": "",
            "reason": "function pointer variable has no local deterministic target binding",
            "resolution_kind": "",
            "supporting_evidence": evidence_text,
            "type_decl": "",
        }

    target, evidence_kind, evidence_text = _resolve_field_target(
        context,
        base_symbol=call.base_symbol,
        field_name=call.member_name,
        scope_key=call.scope_key,
        line=call.line,
    )
    type_decl = _type_decl_for_symbol(
        context,
        call.base_symbol,
        call.member_name,
        scope_key=call.scope_key,
    )
    if target and _resolved_definition_exists(
        inventory,
        target,
        caller_unit_id=caller_unit_id,
    ):
        return {
            "status": "resolved",
            "resolved_target": target,
            "reason": "",
            "resolution_kind": evidence_kind,
            "supporting_evidence": evidence_text,
            "type_decl": type_decl,
        }
    reason = (
        "function-pointer field found, but no local deterministic binding was resolved"
    )
    if not type_decl:
        reason = "indirect member call found, but no supporting function-pointer field type was resolved"
    return {
        "status": "unresolved",
        "resolved_target": "",
        "reason": reason,
        "resolution_kind": "field_decl_only" if type_decl else "",
        "supporting_evidence": evidence_text,
        "type_decl": type_decl,
    }


def _resolve_alias_target(
    context: CFamilyFileContext,
    *,
    symbol: str,
    scope_key: str,
    line: int,
) -> tuple[str, str, str]:
    current = symbol
    evidence_kind = ""
    evidence_text = ""
    for _ in range(3):
        macro_target = _resolve_macro_alias_target(context, current)
        if macro_target and macro_target != current:
            current = macro_target
        binding = _latest_alias_binding(context, current, scope_key, line)
        if binding is None:
            break
        current = binding.target_symbol
        evidence_kind = binding.evidence_kind
        evidence_text = binding.evidence_text
    if current != symbol:
        return current, evidence_kind, evidence_text
    return "", "", evidence_text


def _resolve_field_target(
    context: CFamilyFileContext,
    *,
    base_symbol: str,
    field_name: str,
    scope_key: str,
    line: int,
) -> tuple[str, str, str]:
    candidates = [base_symbol]
    alias_target, _, _ = _resolve_alias_target(
        context,
        symbol=base_symbol,
        scope_key=scope_key,
        line=line,
    )
    if alias_target:
        candidates.append(alias_target)
    for candidate in candidates:
        binding = _latest_field_binding(context, candidate, field_name, scope_key, line)
        if binding is not None:
            resolved = _resolve_macro_alias_target(context, binding.target_symbol)
            return (
                resolved or binding.target_symbol,
                binding.evidence_kind,
                binding.evidence_text,
            )
    return "", "", ""


def _latest_alias_binding(
    context: CFamilyFileContext,
    symbol: str,
    scope_key: str,
    line: int,
) -> CFamilyAliasBinding | None:
    matches = [
        binding
        for binding in context.alias_bindings
        if binding.symbol == symbol
        and binding.line <= line
        and binding.scope_key in {scope_key, GLOBAL_SCOPE}
    ]
    if not matches:
        return None
    matches.sort(key=lambda item: item.line)
    return matches[-1]


def _latest_field_binding(
    context: CFamilyFileContext,
    base_symbol: str,
    field_name: str,
    scope_key: str,
    line: int,
) -> CFamilyFieldBinding | None:
    matches = [
        binding
        for binding in context.field_bindings
        if binding.base_symbol == base_symbol
        and binding.field_name == field_name
        and binding.line <= line
        and binding.scope_key in {scope_key, GLOBAL_SCOPE}
    ]
    if not matches:
        return None
    matches.sort(key=lambda item: item.line)
    return matches[-1]


def _type_decl_for_symbol(
    context: CFamilyFileContext,
    base_symbol: str,
    field_name: str,
    *,
    scope_key: str,
) -> str:
    type_name = _type_for_symbol(context, base_symbol, scope_key)
    if not type_name:
        alias = _latest_alias_binding(context, base_symbol, scope_key, 10**9)
        if alias is not None:
            type_name = _type_for_symbol(context, alias.target_symbol, alias.scope_key)
    if not type_name:
        return ""
    for decl in context.type_decls:
        if decl.name == type_name and field_name in decl.function_pointer_fields:
            return decl.text
    return ""


def _type_for_symbol(
    context: CFamilyFileContext,
    symbol: str,
    scope_key: str,
) -> str:
    matches = [
        item
        for item in context.variable_types
        if item.symbol == symbol and item.scope_key in {scope_key, GLOBAL_SCOPE}
    ]
    if not matches:
        return ""
    matches.sort(key=lambda item: (item.scope_key != scope_key, item.line))
    return matches[-1].type_name


def _resolved_definition_exists(
    inventory: dict[str, Any] | StaticInventory,
    symbol: str,
    *,
    caller_unit_id: str,
) -> bool:
    if isinstance(inventory, StaticInventory):
        return bool(
            find_symbol_definitions(
                inventory,
                symbol,
                caller_unit_id=caller_unit_id,
            )
        )
    symbols = inventory.get("symbols") or {}
    return bool((symbols.get(symbol) or {}).get("definitions"))


def _function_pointer_fields(node: Any, source: bytes) -> list[str]:
    out: list[str] = []

    def walk(current):
        node_type = str(getattr(current, "type", "") or "")
        if node_type == "function_declarator":
            declarator = _child_by_field(current, "declarator")
            name = _identifier_from_node(declarator or current, source)
            if name and _contains_pointer_declarator(current):
                out.append(name)
        for child in getattr(current, "children", []) or []:
            walk(child)

    walk(node)
    return _dedup_keep_order(out)


def _contains_pointer_declarator(node: Any) -> bool:
    if node is None:
        return False
    if str(getattr(node, "type", "") or "") == "pointer_declarator":
        return True
    return any(
        _contains_pointer_declarator(child)
        for child in getattr(node, "children", []) or []
    )


def _contains_function_pointer_declarator(node: Any) -> bool:
    if node is None:
        return False
    if str(getattr(node, "type", "") or "") == "function_declarator":
        return _contains_pointer_declarator(node)
    return any(
        _contains_function_pointer_declarator(child)
        for child in getattr(node, "children", []) or []
    )


def _declaration_contains_function_pointer(node: Any) -> bool:
    return any(
        _contains_function_pointer_declarator(child)
        for child in getattr(node, "children", []) or []
    )


def _type_name_from_declaration(node: Any, source: bytes) -> str:
    for child in getattr(node, "children", []) or []:
        node_type = str(getattr(child, "type", "") or "")
        if node_type in {
            "type_identifier",
            "primitive_type",
            "sized_type_specifier",
            "struct_specifier",
            "class_specifier",
        }:
            text = _node_text(child, source).strip()
            if node_type in {"struct_specifier", "class_specifier"}:
                name = _identifier_from_node(_child_by_field(child, "name"), source)
                if name:
                    return name
            if text:
                parts = text.split()
                return parts[-1]
    return ""


def _extract_designated_bindings(node: Any, source: bytes) -> list[tuple[str, str]]:
    if node is None:
        return []
    out: list[tuple[str, str]] = []

    def walk(current):
        node_type = str(getattr(current, "type", "") or "")
        if node_type == "initializer_pair":
            field_name = ""
            target_symbol = ""
            for child in getattr(current, "children", []) or []:
                child_type = str(getattr(child, "type", "") or "")
                if child_type == "field_designator":
                    field_name = _identifier_from_node(child, source)
                if child_type not in {"field_designator", "subscript_designator"}:
                    target_symbol = (
                        _extract_direct_symbol(child, source) or target_symbol
                    )
            if field_name and target_symbol:
                out.append((field_name, target_symbol))
        for child in getattr(current, "children", []) or []:
            walk(child)

    walk(node)
    return out


def _extract_direct_symbol(node: Any, source: bytes) -> str:
    if node is None:
        return ""
    text = _node_text(node, source).strip()
    if not text:
        return ""
    match = _DIRECT_ASSIGN_RE.match(text)
    if match:
        return str(match.group(1) or "")
    node_type = str(getattr(node, "type", "") or "")
    if node_type in {"identifier", "field_identifier"}:
        return _identifier_from_node(node, source)
    for child in getattr(node, "children", []) or []:
        if str(getattr(child, "type", "") or "") in {"identifier", "field_identifier"}:
            return _identifier_from_node(child, source)
    return ""


def _resolve_member_target_from_node(
    node: Any,
    source: bytes,
    context: CFamilyFileContext,
    *,
    scope_key: str,
    line: int,
) -> str:
    if node is None:
        return ""
    base_symbol, field_name = _member_access_parts(node, source)
    if not base_symbol or not field_name:
        return ""
    target, _kind, _evidence = _resolve_field_target(
        context,
        base_symbol=base_symbol,
        field_name=field_name,
        scope_key=scope_key,
        line=line,
    )
    return target


def _member_access_parts(node: Any, source: bytes) -> tuple[str, str]:
    identifiers: list[str] = []

    def walk(current):
        current_type = str(getattr(current, "type", "") or "")
        if current_type in {"identifier", "field_identifier"}:
            ident = _node_text(current, source).strip()
            if ident:
                identifiers.append(ident)
        for child in getattr(current, "children", []) or []:
            walk(child)

    walk(node)
    if len(identifiers) < 2:
        text = _node_text(node, source).strip()
        if "->" in text:
            parts = [part.strip("() ") for part in text.split("->", 1)]
            if len(parts) == 2:
                return parts[0], parts[1]
        if "." in text:
            parts = [part.strip("() ") for part in text.split(".", 1)]
            if len(parts) == 2:
                return parts[0], parts[1]
        return "", ""
    return identifiers[0], identifiers[-1]


def _child_by_field(node: Any, name: str) -> Any | None:
    try:
        return node.child_by_field_name(name)
    except Exception:
        return None


def _first_non_initializer_child(node: Any) -> Any | None:
    for child in getattr(node, "children", []) or []:
        child_type = str(getattr(child, "type", "") or "")
        if child_type not in {"=", "initializer_list"}:
            return child
    return None


def _find_initializer_node(node: Any) -> Any | None:
    for child in getattr(node, "children", []) or []:
        child_type = str(getattr(child, "type", "") or "")
        if child_type in {
            "initializer_list",
            "identifier",
            "unary_expression",
            "call_expression",
            "field_expression",
            "pointer_expression",
        }:
            return child
    children = list(getattr(node, "children", []) or [])
    return children[-1] if children else None


def _typedef_alias_name(text: str) -> str:
    match = _TYPEDEF_ALIAS_RE.search(text)
    return str(match.group(1) or "") if match else ""


def _typedef_function_pointer_alias(text: str) -> str:
    match = re.search(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", text)
    if match:
        return str(match.group(1) or "")
    generic = _GENERIC_TYPEDEF_ALIAS_RE.search(text)
    return str(generic.group(1) or "") if generic else ""


def _language_for_file(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    if ext in {".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}:
        return "cpp"
    return "c"


def _collect_macro_definitions(
    *,
    codebase_path: Path,
    file_path: str,
    source_text: str,
    depth: int,
) -> list[CFamilyMacroDef]:
    files = [(file_path, source_text)]
    files.extend(
        _collect_include_files(
            codebase_path=codebase_path,
            file_path=file_path,
            source_text=source_text,
            depth=depth,
        )
    )
    out: list[CFamilyMacroDef] = []
    seen: set[tuple[str, str, int]] = set()
    for rel_path, text in files:
        lines = text.splitlines()
        idx = 0
        while idx < len(lines):
            raw = lines[idx]
            match = _MACRO_DEFINE_RE.match(raw)
            if not match:
                idx += 1
                continue
            name = str(match.group(1) or "")
            params = str(match.group(3) or "")
            body = str(match.group(4) or "").rstrip()
            start_line = idx + 1
            block = [raw]
            while block[-1].rstrip().endswith("\\") and idx + 1 < len(lines):
                idx += 1
                block.append(lines[idx])
            if name:
                key = (name, rel_path, start_line)
                if key not in seen:
                    seen.add(key)
                    expanded_body = (
                        body
                        or "\n".join(line.rstrip("\\").rstrip() for line in block)
                        .split(name, 1)[-1]
                        .strip()
                    )
                    out.append(
                        CFamilyMacroDef(
                            name=name,
                            body=expanded_body,
                            file_path=rel_path,
                            line=start_line,
                            is_function_like=bool(match.group(2)),
                            parameters=tuple(
                                p.strip() for p in params.split(",") if p.strip()
                            ),
                        )
                    )
            idx += 1
    out.sort(key=lambda item: (item.file_path, item.line, item.name))
    return out


def _collect_include_files(
    *,
    codebase_path: Path,
    file_path: str,
    source_text: str,
    depth: int,
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def visit(rel_path: str, text: str, remaining: int) -> None:
        if remaining <= 0:
            return
        current_path = (codebase_path / rel_path).resolve()
        for include in parse_includes_from_text(text):
            resolved = resolve_include_path(
                include=include,
                current_path=current_path,
                root=codebase_path,
            )
            if resolved is None:
                continue
            try:
                include_rel = resolved.relative_to(codebase_path).as_posix()
            except Exception:
                continue
            if include_rel in seen:
                continue
            seen.add(include_rel)
            include_text = resolved.read_text(encoding="utf-8", errors="ignore")
            out.append((include_rel, include_text))
            visit(include_rel, include_text, remaining - 1)

    visit(file_path, source_text, depth)
    return out


def _resolve_macro_alias_target(context: CFamilyFileContext, symbol: str) -> str:
    chain = _expand_macro_chain(context, symbol)
    if not chain:
        return ""
    terminal = _macro_terminal_text(chain[-1])
    if not terminal:
        return ""
    return terminal


def _expand_macro_chain(
    context: CFamilyFileContext,
    macro_name: str,
    *,
    max_depth: int = 5,
) -> list[CFamilyMacroDef]:
    chain: list[CFamilyMacroDef] = []
    seen: set[str] = set()
    current = macro_name
    for _ in range(max_depth):
        macro = _latest_macro_definition(context, current)
        if macro is None or macro.name in seen:
            break
        chain.append(macro)
        seen.add(macro.name)
        next_name = _macro_alias_target_name(macro)
        if not next_name:
            break
        current = next_name
    return chain


def _latest_macro_definition(
    context: CFamilyFileContext,
    macro_name: str,
) -> CFamilyMacroDef | None:
    matches = [macro for macro in context.macro_definitions if macro.name == macro_name]
    if not matches:
        return None
    matches.sort(key=lambda item: (item.file_path, item.line))
    return matches[-1]


def _macro_alias_target_name(macro: CFamilyMacroDef) -> str:
    body = str(macro.body or "").strip()
    if not body:
        return ""
    tokens = _MACRO_TOKEN_RE.findall(body)
    if not tokens:
        return ""
    if macro.is_function_like:
        first = tokens[0]
        if first == macro.name or first in set(macro.parameters):
            return ""
        return first
    if len(tokens) == 1 and tokens[0] != macro.name:
        return tokens[0]
    if tokens and tokens[0] != macro.name:
        return tokens[0]
    return ""


def _macro_signature(macro: CFamilyMacroDef) -> str:
    if macro.is_function_like:
        params = ", ".join(macro.parameters)
        return f"#define {macro.name}({params}) {macro.body}".strip()
    return f"#define {macro.name} {macro.body}".strip()


def _macro_terminal_text(macro: CFamilyMacroDef) -> str:
    body = str(macro.body or "").strip()
    if not body:
        return ""
    tokens = _MACRO_TOKEN_RE.findall(body)
    if len(tokens) == 1 and body == tokens[0]:
        return tokens[0]
    if body.startswith("(") and body.endswith(")"):
        inner = body[1:-1].strip()
        if _DIRECT_ASSIGN_RE.match(inner):
            return inner.lstrip("&").strip()
    if _DIRECT_ASSIGN_RE.match(body):
        return body.lstrip("&").strip()
    return body


def _unit_source_text(unit: Any, *, codebase_path: str | Path) -> str:
    file_path = str(_unit_get(unit, "file_path", "") or "")
    start_line = int(_unit_get(unit, "start_line", 0) or 0)
    end_line = int(_unit_get(unit, "end_line", 0) or 0)
    if not file_path or start_line <= 0 or end_line < start_line:
        return ""
    abs_path = (Path(codebase_path).resolve() / file_path).resolve()
    if not abs_path.is_file():
        return ""
    lines = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return "\n".join(lines[start_line - 1 : end_line])


def _is_function_pointer_variable(
    context: CFamilyFileContext,
    symbol: str,
    scope_key: str,
) -> bool:
    return (scope_key, symbol) in context.function_pointer_variables or (
        GLOBAL_SCOPE,
        symbol,
    ) in context.function_pointer_variables


def _has_local_alias_binding(
    context: CFamilyFileContext,
    symbol: str,
    scope_key: str,
) -> bool:
    return any(
        binding.symbol == symbol and binding.scope_key == scope_key
        for binding in context.alias_bindings
    )


def _scope_key_for_function(node: Any, source: bytes) -> str:
    declarator = _child_by_field(node, "declarator")
    name = _identifier_from_node(declarator or node, source) or "anonymous"
    return f"{name}:{_node_line(node)}"


def _unit_get(unit: Any, key: str, default: Any = None) -> Any:
    if isinstance(unit, dict):
        return unit.get(key, default)
    return getattr(unit, key, default)


def _indent_block(text: str, *, prefix: str = "  ") -> list[str]:
    if not text:
        return []
    return [
        f"{prefix}{line}" if line else prefix.rstrip() for line in text.splitlines()
    ]


def _dedup_keep_order(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out
