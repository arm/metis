# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import re

from . import constants as C
from .debug import _emit_debug
from ..types import TriageState
from .evidence_text import (
    _limit_output,
    _parse_grep_hits,
    _token_pattern,
    _extend_hits,
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
) -> tuple[str, str, str]:
    line_context = ""
    file_head_context = ""
    exact_line_context = ""

    if not file_path:
        return line_context, file_head_context, exact_line_context

    start = max(1, line - C.FILE_WINDOW_RADIUS)
    end = line + C.FILE_WINDOW_RADIUS
    window = _safe_tool_capture(
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
    if window:
        line_context += "\n" + window

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
        line_context += "\n" + exact

    file_text = _safe_tool_capture(
        state,
        sections,
        tool_name="cat",
        tool_args={"path": file_path},
        error_label="FILE_HEAD_ERROR",
        append_error_section=True,
        emit_debug=False,
        invoke=lambda: tool_runner.cat(file_path),
    )
    if file_text:
        head = "\n".join(file_text.splitlines()[: C.DEFAULT_CAPTURE_MAX_LINES])
        file_head_context = head
        clipped = _limit_output(
            head,
            max_lines=C.DEFAULT_CAPTURE_MAX_LINES,
            max_chars=C.DEFAULT_CAPTURE_MAX_CHARS,
        )
        sections.append(f"[FILE_HEAD {file_path}]\n{clipped}")
        _emit_debug(
            state,
            "tool_call",
            tool_name="cat",
            tool_args={"path": file_path},
            tool_output=clipped,
        )

    return line_context, file_head_context, exact_line_context


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


def _expand_related_paths(tool_runner, related_paths: list[str]) -> list[str]:
    expanded_related: list[str] = []
    seen_related: set[str] = set()
    for rel_path in related_paths[: C.RELATED_PATH_INPUT_LIMIT]:
        if "/" not in rel_path:
            found_any = False
            try:
                for found in tool_runner.find_name(
                    rel_path, max_results=C.FIND_NAME_MAX_RESULTS
                ):
                    found_any = True
                    if found in seen_related:
                        continue
                    seen_related.add(found)
                    expanded_related.append(found)
                    if len(expanded_related) >= C.EXPANDED_RELATED_MAX:
                        break
            except Exception:
                found_any = False
            if found_any:
                if len(expanded_related) >= C.EXPANDED_RELATED_MAX:
                    break
                continue
        if rel_path in seen_related:
            continue
        seen_related.add(rel_path)
        expanded_related.append(rel_path)
        if len(expanded_related) >= C.EXPANDED_RELATED_MAX:
            break
    return expanded_related


def _collect_readable_related_paths(
    state: TriageState,
    sections: list[str],
    *,
    tool_runner,
    expanded_related: list[str],
) -> list[str]:
    readable_related: list[str] = []
    for rel_path in sorted(
        expanded_related[: C.READABLE_RELATED_MAX], key=lambda p: p.lower()
    ):
        related_text = _safe_tool_capture(
            state,
            sections,
            tool_name="cat",
            tool_args={"path": rel_path},
            section_label=f"RELATED_FILE {rel_path}",
            max_lines=C.DEFAULT_CAPTURE_MAX_LINES,
            max_chars=C.DEFAULT_CAPTURE_MAX_CHARS,
            append_error_section=False,
            invoke=lambda rp=rel_path: tool_runner.cat(rp),
        )
        if related_text is not None:
            readable_related.append(rel_path)
    return readable_related


def _collect_term_hits(
    state: TriageState,
    sections: list[str],
    *,
    tool_runner,
    term: str,
    pattern: str,
    readable_related: list[str],
    fallback_paths: list[str],
    followup_hits: list[tuple[str, int]],
    definition_hints: set[str],
    max_followup_hits: int,
    max_sections: int,
) -> None:
    for rel_path in readable_related[: C.READABLE_RELATED_MAX]:
        if len(followup_hits) >= max_followup_hits or len(sections) >= max_sections:
            break
        output = _safe_tool_capture(
            state,
            sections,
            tool_name="grep",
            tool_args={"pattern": pattern, "path": rel_path},
            section_label=f"RELATED_GREP {term} IN {rel_path}",
            max_lines=C.RELATED_GREP_MAX_LINES,
            max_chars=C.RELATED_GREP_MAX_CHARS,
            append_error_section=False,
            invoke=lambda rp=rel_path: tool_runner.grep(pattern, rp),
        )
        if output is None:
            continue
        parsed = _parse_grep_hits(output)
        _extend_hits(followup_hits, parsed, max_total=max_followup_hits)

    for grep_path in fallback_paths:
        if len(followup_hits) >= max_followup_hits or len(sections) >= max_sections:
            break
        output = _safe_tool_capture(
            state,
            sections,
            tool_name="grep",
            tool_args={"pattern": pattern, "path": grep_path},
            section_label=f"GREP {term} IN {grep_path}",
            error_label=f"GREP_ERROR {term}",
            max_lines=C.FALLBACK_GREP_MAX_LINES,
            max_chars=C.FALLBACK_GREP_MAX_CHARS,
            append_error_section=True,
            invoke=lambda gp=grep_path: tool_runner.grep(pattern, gp),
        )
        if output is None:
            continue
        parsed = _parse_grep_hits(output)
        _extend_hits(followup_hits, parsed, max_total=max_followup_hits)

    for probe in (
        rf"(^|[^A-Za-z0-9_]){re.escape(term)}\s*\(",
        rf"(^|[^A-Za-z0-9_]){re.escape(term)}\s*=",
        rf"^\s*(def|class|function|fn|interface|type)\s+{re.escape(term)}([^A-Za-z0-9_]|$)",
    ):
        if len(followup_hits) >= max_followup_hits or len(sections) >= max_sections:
            break
        for probe_path in fallback_paths[: C.PROBE_FALLBACK_PATHS]:
            output = _safe_tool_capture(
                state,
                sections,
                tool_name="grep",
                tool_args={"pattern": probe, "path": probe_path},
                section_label=f"GREP_PROBE {term} / {probe} IN {probe_path}",
                max_lines=C.RELATED_GREP_MAX_LINES,
                max_chars=C.RELATED_GREP_MAX_CHARS,
                append_error_section=False,
                invoke=lambda pp=probe_path: tool_runner.grep(probe, pp),
            )
            if output is None:
                continue
            parsed = _parse_grep_hits(output)
            _extend_hits(followup_hits, parsed, max_total=max_followup_hits)
            if parsed:
                for hit_path, hit_line in parsed[: C.PROBE_HINT_HITS]:
                    definition_hints.add(f"{term} @ {hit_path}:{hit_line}")
                break


def _gather_symbol_hits(
    state: TriageState,
    sections: list[str],
    *,
    tool_runner,
    terms: list[str],
    file_path: str,
    related_paths: list[str],
    max_followup_hits: int,
    max_sections: int,
) -> tuple[list[tuple[str, int]], set[str]]:
    followup_hits: list[tuple[str, int]] = []
    definition_hints: set[str] = set()

    expanded_related = _expand_related_paths(tool_runner, related_paths)
    readable_related = _collect_readable_related_paths(
        state,
        sections,
        tool_runner=tool_runner,
        expanded_related=expanded_related,
    )

    fallback_paths = _build_fallback_paths(file_path)
    for term in terms:
        if len(sections) >= max_sections:
            break
        pattern = _token_pattern(term)
        _collect_term_hits(
            state,
            sections,
            tool_runner=tool_runner,
            term=term,
            pattern=pattern,
            readable_related=readable_related,
            fallback_paths=fallback_paths,
            followup_hits=followup_hits,
            definition_hints=definition_hints,
            max_followup_hits=max_followup_hits,
            max_sections=max_sections,
        )

    return followup_hits, definition_hints


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
