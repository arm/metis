# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os

from . import constants as C
from .debug import _emit_debug
from ..types import TriageState
from .evidence_text import (
    _assignment_pattern,
    _extend_hits,
    _call_pattern,
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
    append_empty_section: bool = True,
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
    if section_label and (append_empty_section or str(output or "").strip()):
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


def _tool_debug_args(toolbox, tool_name: str, **tool_args) -> dict:
    out = dict(tool_args)
    describe = getattr(toolbox, "describe", None)
    if not callable(describe):
        return out
    try:
        details = describe(tool_name)
    except Exception:
        return out
    if not isinstance(details, dict):
        return out
    for key, value in details.items():
        out.setdefault(key, value)
    return out


def _collect_file_context(
    state: TriageState,
    sections: list[str],
    *,
    toolbox,
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
        tool_args=_tool_debug_args(
            toolbox,
            "sed",
            path=file_path,
            start_line=start,
            end_line=end,
        ),
        section_label=f"FILE_WINDOW {file_path}:{start}-{end}",
        error_label="FILE_WINDOW_ERROR",
        max_lines=C.DEFAULT_CAPTURE_MAX_LINES,
        max_chars=C.DEFAULT_CAPTURE_MAX_CHARS,
        append_error_section=True,
        invoke=lambda: toolbox.sed(file_path, start, end),
    )
    exact = _safe_tool_capture(
        state,
        sections,
        tool_name="sed",
        tool_args=_tool_debug_args(
            toolbox,
            "sed",
            path=file_path,
            start_line=line,
            end_line=line,
        ),
        section_label=f"REPORTED_LINE {file_path}:{line}",
        error_label="REPORTED_LINE_ERROR",
        max_lines=C.REPORTED_LINE_MAX_LINES,
        max_chars=C.REPORTED_LINE_MAX_CHARS,
        append_error_section=True,
        invoke=lambda: toolbox.sed(file_path, line, line),
    )
    if exact:
        exact_line_context = exact

    return exact_line_context


def _build_fallback_paths(file_path: str) -> list[str]:
    fallback_paths: list[str] = []
    if file_path:
        file_dir = os.path.dirname(file_path)
        if file_dir:
            fallback_paths.append(file_dir)
        top = file_path.split("/", 1)[0]
        if top and top not in fallback_paths:
            fallback_paths.append(top)
    if not fallback_paths:
        fallback_paths = ["."]
    return sorted(set(fallback_paths), key=lambda p: p.lower())


def _gather_symbol_definition_hits(
    state: TriageState,
    sections: list[str],
    *,
    toolbox,
    symbols: list[str],
    file_path: str,
    max_followup_hits: int,
    max_sections: int,
) -> tuple[list[tuple[str, int]], set[str], list[str]]:
    followup_hits: list[tuple[str, int]] = []
    definition_hints: set[str] = set()

    if not symbols:
        return followup_hits, definition_hints, []

    local_path = file_path or "."

    def _probe_symbol(symbol: str, path: str, mode: str) -> bool:
        if len(sections) >= max_sections or len(followup_hits) >= max_followup_hits:
            return False
        hit_found = False
        probes = (
            _token_pattern(symbol),
            _call_pattern(symbol),
            _assignment_pattern(symbol),
        )
        for probe in probes:
            if len(sections) >= max_sections or len(followup_hits) >= max_followup_hits:
                break
            output = _safe_tool_capture(
                state,
                sections,
                tool_name="grep",
                tool_args=_tool_debug_args(
                    toolbox,
                    "grep",
                    pattern=probe,
                    path=path,
                    mode=mode,
                ),
                section_label=f"SYMBOL_GREP {symbol} IN {path} ({mode})",
                max_lines=C.RELATED_GREP_MAX_LINES,
                max_chars=C.RELATED_GREP_MAX_CHARS,
                append_error_section=False,
                append_empty_section=False,
                invoke=lambda p=path, q=probe: toolbox.grep(q, p),
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
        if not _probe_symbol(symbol, local_path, "local"):
            unresolved.append(symbol)
    return followup_hits, definition_hints, unresolved


def _collect_hit_context_sections(
    state: TriageState,
    sections: list[str],
    *,
    toolbox,
    followup_hits: list[tuple[str, int]],
    max_sections: int,
) -> None:
    seen_ctx: set[tuple[str, int]] = set()
    for path, hit_line in followup_hits:
        if len(sections) >= max_sections:
            break
        if (path, hit_line) in seen_ctx:
            continue
        seen_ctx.add((path, hit_line))
        start = max(1, hit_line - C.HIT_CONTEXT_RADIUS)
        end = hit_line + C.HIT_CONTEXT_RADIUS
        _safe_tool_capture(
            state,
            sections,
            tool_name="sed",
            tool_args=_tool_debug_args(
                toolbox,
                "sed",
                path=path,
                start_line=start,
                end_line=end,
            ),
            section_label=f"HIT_CONTEXT {path}:{start}-{end}",
            error_label=f"HIT_CONTEXT_ERROR {path}:{hit_line}",
            max_lines=C.HIT_CONTEXT_MAX_LINES,
            max_chars=C.HIT_CONTEXT_MAX_CHARS,
            append_error_section=True,
            invoke=lambda p=path, s=start, e=end: toolbox.sed(p, s, e),
        )


def _collect_use_site_sections(
    state: TriageState,
    sections: list[str],
    *,
    toolbox,
    symbols: list[str],
    file_path: str,
    line: int,
    max_sections: int,
) -> None:
    if not symbols or len(sections) >= max_sections:
        return

    paths = _build_fallback_paths(file_path)
    if "." not in paths:
        paths.append(".")
    seen_context: set[tuple[str, int]] = set()
    seen_symbols: set[str] = set()
    for symbol in symbols:
        if len(sections) >= max_sections:
            break
        if symbol in seen_symbols:
            continue
        seen_symbols.add(symbol)
        if len(symbol) < 3:
            continue
        pattern = _call_pattern(symbol)
        for path in paths:
            if len(sections) >= max_sections:
                break
            output = _safe_tool_capture(
                state,
                sections,
                tool_name="grep",
                tool_args=_tool_debug_args(
                    toolbox,
                    "grep",
                    pattern=pattern,
                    path=path,
                    mode="caller_or_wrapper",
                ),
                max_lines=C.RELATED_GREP_MAX_LINES,
                max_chars=C.RELATED_GREP_MAX_CHARS,
                append_error_section=False,
                invoke=lambda p=path, q=pattern: toolbox.grep(q, p),
            )
            if not output:
                continue
            hits = [
                hit
                for hit in _parse_grep_hits(output, max_hits=C.MAX_TARGETED_HITS)
                if not _is_reported_line_hit(hit, file_path=file_path, line=line)
            ]
            if not hits:
                continue
            sections.append(
                f"[CALLER_GREP {symbol} IN {path}]\n"
                f"{_limit_output(output, max_lines=C.RELATED_GREP_MAX_LINES, max_chars=C.RELATED_GREP_MAX_CHARS)}"
            )
            for hit_path, hit_line in hits:
                if len(sections) >= max_sections:
                    break
                if (hit_path, hit_line) in seen_context:
                    continue
                seen_context.add((hit_path, hit_line))
                start = max(1, hit_line - C.TARGETED_HIT_RADIUS)
                end = hit_line + C.TARGETED_HIT_RADIUS
                _safe_tool_capture(
                    state,
                    sections,
                    tool_name="sed",
                    tool_args=_tool_debug_args(
                        toolbox,
                        "sed",
                        path=hit_path,
                        start_line=start,
                        end_line=end,
                    ),
                    section_label=f"CALLER_CONTEXT {hit_path}:{start}-{end}",
                    error_label=f"CALLER_CONTEXT_ERROR {hit_path}:{hit_line}",
                    max_lines=C.TARGETED_HIT_CONTEXT_MAX_LINES,
                    max_chars=C.TARGETED_HIT_CONTEXT_MAX_CHARS,
                    append_error_section=True,
                    invoke=lambda p=hit_path, s=start, e=end: toolbox.sed(p, s, e),
                )
            if seen_context:
                break


def _is_reported_line_hit(
    hit: tuple[str, int], *, file_path: str, line: int, radius: int = 2
) -> bool:
    hit_path, hit_line = hit
    return hit_path == file_path and abs(int(hit_line) - int(line)) <= radius
