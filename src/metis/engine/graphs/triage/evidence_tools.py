# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import re
from typing import Any

from metis.engine.analysis.c_family_macro import (
    collect_c_macro_definition_sections,
    collect_c_macro_like_calls_from_scope,
    is_c_family_file_path,
)

from . import constants as C
from .debug import _emit_debug
from ..types import TriageState
from .evidence_text import (
    _extend_hits,
    _limit_output,
    _parse_grep_hits,
    _token_pattern,
)


def _safe_tool_capture(
    state: TriageState,
    sections: list[str],
    *,
    tool_name: str,
    tool_args: dict,
    section_label: str | None = None,
    error_label: str | None = None,
    max_lines: int = C.DEFAULT_CAPTURE_MAX_LINES,
    max_chars: int = C.DEFAULT_CAPTURE_MAX_CHARS,
    append_error_section: bool = False,
    emit_debug: bool = True,
    invoke,
) -> str | None:
    try:
        output = invoke()
    except Exception as exc:
        if append_error_section and error_label:
            sections.append(f"[{error_label}]\n{exc}")
        if emit_debug:
            _emit_debug(
                state,
                "tool_call",
                tool_name=tool_name,
                tool_args=tool_args,
                tool_output=f"Tool execution failed: {exc}",
            )
        return None

    clipped = _limit_output(output, max_lines=max_lines, max_chars=max_chars)
    if section_label:
        sections.append(f"[{section_label}]\n{clipped}")
    if emit_debug:
        _emit_debug(
            state,
            "tool_call",
            tool_name=tool_name,
            tool_args=tool_args,
            tool_output=clipped,
        )
    return output


def _collect_file_context(
    state: TriageState,
    sections: list[str],
    *,
    tool_runner,
    file_path: str,
    line: int,
    window_radius: int,
) -> str:
    exact_line_context = ""

    if not file_path:
        return exact_line_context

    radius = max(1, int(window_radius or 1))
    start = max(1, line - radius)
    end = line + radius
    _safe_tool_capture(
        state,
        sections,
        tool_name="sed",
        tool_args={"path": file_path, "start_line": start, "end_line": end},
        section_label=f"FILE_WINDOW {file_path}:{start}-{end}",
        error_label="FILE_WINDOW_ERROR",
        max_lines=C.DEFAULT_CAPTURE_MAX_LINES,
        max_chars=C.DEFAULT_CAPTURE_MAX_CHARS,
        append_error_section=True,
        invoke=lambda: tool_runner.sed(file_path, start, end),
    )
    exact = _safe_tool_capture(
        state,
        sections,
        tool_name="sed",
        tool_args={"path": file_path, "start_line": line, "end_line": line},
        section_label=f"REPORTED_LINE {file_path}:{line}",
        error_label="REPORTED_LINE_ERROR",
        max_lines=C.REPORTED_LINE_MAX_LINES,
        max_chars=C.REPORTED_LINE_MAX_CHARS,
        append_error_section=True,
        invoke=lambda: tool_runner.sed(file_path, line, line),
    )
    if exact:
        exact_line_context = exact

    return exact_line_context


def _collect_treesitter_scope_symbols(
    state: TriageState,
    sections: list[str],
    *,
    file_path: str,
    line: int,
    max_symbols: int,
) -> tuple[list[str], list[str]]:
    analyzer = state.get("triage_analyzer")
    if analyzer is None:
        return [], []
    runtime = getattr(analyzer, "runtime", None)
    if runtime is None or not bool(getattr(runtime, "is_available", False)):
        sections.append("[TREE_SITTER_SCOPE]\nunavailable")
        return [], []
    supports_file = getattr(analyzer, "supports_file", None)
    if callable(supports_file):
        try:
            if not supports_file(file_path):
                sections.append("[TREE_SITTER_SCOPE]\nunsupported_file")
                return [], []
        except Exception:
            return [], []
    try:
        parsed = runtime.parse_file(
            state.get("triage_codebase_path", ".") or ".", file_path
        )
    except Exception as exc:
        sections.append(f"[TREE_SITTER_SCOPE]\nparse_failed: {exc}")
        return [], []

    source = bytes(parsed.text, "utf-8")
    root = parsed.tree.root_node
    nodes: list[Any] = []
    parent_map: dict[int, Any | None] = {}

    def _walk(node: Any, parent: Any | None) -> None:
        nodes.append(node)
        parent_map[id(node)] = parent
        for child in getattr(node, "children", []) or []:
            _walk(child, node)

    _walk(root, None)
    anchor = _find_anchor_node(nodes, line=line)
    if anchor is None:
        sections.append("[TREE_SITTER_SCOPE]\nanchor_not_found")
        return [], []
    scope = _nearest_enclosing_scope(anchor, parent_map)
    if scope is None:
        scope = anchor

    scope_start = int(getattr(scope, "start_point", (0, 0))[0]) + 1
    scope_end = int(getattr(scope, "end_point", (0, 0))[0]) + 1
    sections.append(
        f"[TREE_SITTER_SCOPE {file_path}:{scope_start}-{scope_end}]\ntype={getattr(scope, 'type', '')}"
    )

    line_symbols = _collect_identifier_symbols(
        anchor, source, max_symbols=max_symbols * 2
    )
    upward_symbols = _collect_identifier_symbols_until_line(
        scope,
        source,
        line=line,
        max_symbols=max_symbols * 4,
    )
    merged: list[str] = []
    seen: set[str] = set()
    for symbol in line_symbols + upward_symbols:
        if not symbol or symbol in seen:
            continue
        seen.add(symbol)
        merged.append(symbol)
        if len(merged) >= max_symbols:
            break
    macros: list[str] = []
    if is_c_family_file_path(file_path):
        macros = collect_c_macro_like_calls_from_scope(
            scope,
            source,
            max_macros=max_symbols,
            collect_identifier_symbols=_collect_identifier_symbols,
        )
    if merged:
        sections.append("[TREE_SITTER_SCOPE_SYMBOLS]\n" + ", ".join(merged))
    if macros:
        sections.append("[TREE_SITTER_MACROS]\n" + ", ".join(macros))
    return merged, macros


def _find_anchor_node(nodes: list[Any], *, line: int) -> Any | None:
    best = None
    best_score = 1_000_000
    best_span = 1_000_000
    for node in nodes:
        start = int(getattr(node, "start_point", (0, 0))[0]) + 1
        end = int(getattr(node, "end_point", (0, 0))[0]) + 1
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


def _nearest_enclosing_scope(
    node: Any, parent_map: dict[int, Any | None]
) -> Any | None:
    scope_types = {
        "function_definition",
        "method_definition",
        "function_declaration",
        "compound_statement",
        "block",
        "if_statement",
        "while_statement",
        "for_statement",
        "switch_statement",
    }
    cur = node
    while cur is not None:
        if str(getattr(cur, "type", "") or "") in scope_types:
            return cur
        cur = parent_map.get(id(cur))
    return None


def _collect_identifier_symbols(
    node: Any, source: bytes, *, max_symbols: int
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def _walk(cur: Any) -> None:
        nonlocal out
        if len(out) >= max_symbols:
            return
        node_type = str(getattr(cur, "type", "") or "")
        if node_type in {"identifier", "field_identifier"}:
            text = _node_text(cur, source).strip()
            if _is_symbol_like(text) and text not in seen:
                seen.add(text)
                out.append(text)
        for child in getattr(cur, "children", []) or []:
            _walk(child)

    _walk(node)
    return out


def _collect_identifier_symbols_until_line(
    node: Any,
    source: bytes,
    *,
    line: int,
    max_symbols: int,
) -> list[str]:
    scored: dict[str, int] = {}

    def _walk(cur: Any) -> None:
        start = int(getattr(cur, "start_point", (0, 0))[0]) + 1
        if start > line:
            return
        node_type = str(getattr(cur, "type", "") or "")
        if node_type in {"identifier", "field_identifier"}:
            text = _node_text(cur, source).strip()
            if _is_symbol_like(text):
                distance = abs(line - start)
                score = max(0, 1000 - min(distance, 1000))
                prev = scored.get(text)
                if prev is None or score > prev:
                    scored[text] = score
        for child in getattr(cur, "children", []) or []:
            _walk(child)

    _walk(node)
    ordered = sorted(scored.items(), key=lambda kv: (-kv[1], kv[0].lower()))
    return [symbol for symbol, _ in ordered[:max_symbols]]


def _node_text(node: Any, source: bytes) -> str:
    start = int(getattr(node, "start_byte", 0) or 0)
    end = int(getattr(node, "end_byte", 0) or 0)
    try:
        return source[start:end].decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _is_symbol_like(text: str) -> bool:
    value = str(text or "").strip()
    if not value:
        return False
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{1,127}$", value):
        return False
    return True


def _collect_macro_definition_sections(
    state: TriageState,
    sections: list[str],
    *,
    tool_runner,
    file_path: str,
    macro_names: list[str],
    max_sections: int,
) -> tuple[list[str], dict[str, str]]:
    if not is_c_family_file_path(file_path) or not macro_names:
        return [], {}

    def _dispatch_invoke(invoke):
        op = invoke()
        if not isinstance(op, tuple) or not op:
            return None
        kind = op[0]
        if kind == "grep" and len(op) == 3:
            _, path, pattern = op
            return tool_runner.grep(pattern, path)
        if kind == "sed" and len(op) == 4:
            _, path, start, end = op
            return tool_runner.sed(path, start, end)
        return None

    def _safe_capture(
        *,
        tool_name: str,
        tool_args: dict,
        section_label: str | None = None,
        max_lines: int = C.DEFAULT_CAPTURE_MAX_LINES,
        max_chars: int = C.DEFAULT_CAPTURE_MAX_CHARS,
        append_error_section: bool = False,
        invoke,
    ) -> str | None:
        return _safe_tool_capture(
            state,
            sections,
            tool_name=tool_name,
            tool_args=tool_args,
            section_label=section_label,
            max_lines=max_lines,
            max_chars=max_chars,
            append_error_section=append_error_section,
            invoke=lambda: _dispatch_invoke(invoke),
        )

    return collect_c_macro_definition_sections(
        sections=sections,
        file_path=file_path,
        macro_names=macro_names,
        max_sections=max_sections,
        max_citations=C.MAX_CITATIONS,
        related_grep_max_lines=C.RELATED_GREP_MAX_LINES,
        related_grep_max_chars=C.RELATED_GREP_MAX_CHARS,
        max_targeted_hits=C.MAX_TARGETED_HITS,
        max_targeted_context_hits=C.MAX_TARGETED_CONTEXT_HITS,
        targeted_hit_radius=C.TARGETED_HIT_RADIUS,
        targeted_hit_context_max_lines=C.TARGETED_HIT_CONTEXT_MAX_LINES,
        targeted_hit_context_max_chars=C.TARGETED_HIT_CONTEXT_MAX_CHARS,
        safe_tool_capture=_safe_capture,
        parse_grep_hits=_parse_grep_hits,
        find_name_paths=lambda name: tool_runner.find_name(
            name,
            max_results=C.FIND_NAME_MAX_RESULTS,
        ),
        root_probe_path=".",
    )


def _build_fallback_paths(file_path: str, global_scope: str = ".") -> list[str]:
    fallback_paths: list[str] = []
    if file_path:
        file_dir = os.path.dirname(file_path)
        if file_dir:
            fallback_paths.append(file_dir)
        top = file_path.split("/", 1)[0]
        if top and top not in fallback_paths:
            fallback_paths.append(top)
    if not fallback_paths:
        fallback_paths = [global_scope]
    return sorted(set(fallback_paths), key=lambda p: p.lower())


def _gather_symbol_definition_hits(
    state: TriageState,
    sections: list[str],
    *,
    tool_runner,
    symbols: list[str],
    file_path: str,
    max_followup_hits: int,
    max_sections: int,
    scope_mode: str = "line_local",
) -> tuple[list[tuple[str, int]], set[str], list[str]]:
    followup_hits: list[tuple[str, int]] = []
    definition_hints: set[str] = set()
    resolved: set[str] = set()

    if not symbols:
        return followup_hits, definition_hints, []

    line_local = str(scope_mode or "").strip().lower() == "line_local"
    fallback_paths = (
        [file_path] if line_local and file_path else _build_fallback_paths(file_path)
    )
    local_path = (
        file_path if file_path else (fallback_paths[0] if fallback_paths else ".")
    )

    def _probe_symbol(symbol: str, path: str, mode: str) -> bool:
        if len(sections) >= max_sections or len(followup_hits) >= max_followup_hits:
            return False
        hit_found = False
        probes = (
            _token_pattern(symbol),
            rf"(^|[^A-Za-z0-9_]){re.escape(symbol)}\\s*\\(",
            rf"(^|[^A-Za-z0-9_]){re.escape(symbol)}\\s*=",
        )
        for probe in probes:
            if len(sections) >= max_sections or len(followup_hits) >= max_followup_hits:
                break
            output = _safe_tool_capture(
                state,
                sections,
                tool_name="grep",
                tool_args={"pattern": probe, "path": path, "mode": mode},
                section_label=f"SYMBOL_GREP {symbol} IN {path} ({mode})",
                max_lines=C.RELATED_GREP_MAX_LINES,
                max_chars=C.RELATED_GREP_MAX_CHARS,
                append_error_section=False,
                invoke=lambda p=path, q=probe: tool_runner.grep(q, p),
            )
            if output is None:
                continue
            parsed = _parse_grep_hits(output)
            if parsed:
                hit_found = True
                _extend_hits(followup_hits, parsed, max_total=max_followup_hits)
                for hit_path, hit_line in parsed[: C.PROBE_HINT_HITS]:
                    definition_hints.add(f"{symbol} @ {hit_path}:{hit_line}")
        return hit_found

    unresolved: list[str] = []
    for symbol in symbols:
        if len(sections) >= max_sections:
            break
        if _probe_symbol(symbol, local_path, "local"):
            resolved.add(symbol)
        else:
            unresolved.append(symbol)

    unresolved_remaining: list[str] = []
    for symbol in unresolved:
        if len(sections) >= max_sections:
            unresolved_remaining.append(symbol)
            continue
        found = False
        for path in fallback_paths:
            if len(sections) >= max_sections:
                break
            if _probe_symbol(symbol, path, "fallback"):
                resolved.add(symbol)
                found = True
                break
        if not found:
            unresolved_remaining.append(symbol)

    return followup_hits, definition_hints, unresolved_remaining


def _collect_hit_context_sections(
    state: TriageState,
    sections: list[str],
    *,
    tool_runner,
    followup_hits: list[tuple[str, int]],
    max_followup_hits: int,
    max_sections: int,
) -> None:
    seen_ctx: set[tuple[str, int]] = set()
    for path, hit_line in followup_hits:
        if len(sections) >= max_sections:
            break
        if (path, hit_line) in seen_ctx:
            continue
        seen_ctx.add((path, hit_line))
        if len(seen_ctx) > max_followup_hits:
            break
        start = max(1, hit_line - C.HIT_CONTEXT_RADIUS)
        end = hit_line + C.HIT_CONTEXT_RADIUS
        _safe_tool_capture(
            state,
            sections,
            tool_name="sed",
            tool_args={"path": path, "start_line": start, "end_line": end},
            section_label=f"HIT_CONTEXT {path}:{start}-{end}",
            error_label=f"HIT_CONTEXT_ERROR {path}:{hit_line}",
            max_lines=C.HIT_CONTEXT_MAX_LINES,
            max_chars=C.HIT_CONTEXT_MAX_CHARS,
            append_error_section=True,
            invoke=lambda p=path, s=start, e=end: tool_runner.sed(p, s, e),
        )
