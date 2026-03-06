# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.analysis.base import AnalyzerRequest

from . import constants as C
from .adjudication import is_cross_boundary_unresolved_hop
from .debug import _emit_debug
from ..types import TriageState
from .evidence_text import _parse_grep_hits, _token_pattern
from .evidence_tools import _safe_tool_capture, _build_fallback_paths


def _append_labeled_lines(
    sections: list[str], label: str, lines: list[str], *, limit: int = C.MAX_CITATIONS
) -> None:
    if not lines:
        return
    sections.append(f"[{label}]\n" + "\n".join(lines[:limit]))


def _collect_analyzer_sections(
    state: TriageState,
    sections: list[str],
    *,
    file_path: str,
    line: int,
    candidate_symbols: list[str],
    max_sections: int,
) -> tuple[bool, bool, list[str], list[str]]:
    analyzer = state.get("triage_analyzer")
    if analyzer is None:
        return False, False, [], []
    if len(sections) >= max_sections:
        return False, False, [], []

    try:
        req = AnalyzerRequest(
            codebase_path=state.get("triage_codebase_path", ".") or ".",
            file_path=file_path,
            line=line,
            finding_message=state.get("finding_message", "") or "",
            finding_snippet=state.get("finding_snippet", "") or "",
            finding_rule_id=state.get("finding_rule_id", "") or "",
            candidate_symbols=candidate_symbols,
            max_citations=C.MAX_CITATIONS,
        )
        evidence = analyzer.collect_evidence(req)
    except Exception as exc:
        _emit_debug(
            state,
            "tool_call",
            tool_name="triage_analyzer",
            tool_args={"file_path": file_path, "line": line},
            tool_output=f"Analyzer execution failed: {exc}",
        )
        return False, False, [], []

    _emit_debug(
        state,
        "tool_call",
        tool_name="triage_analyzer",
        tool_args={"file_path": file_path, "line": line, "symbols": candidate_symbols},
        tool_output={
            "supported": bool(getattr(evidence, "supported", False)),
            "language": getattr(evidence, "language", ""),
            "summary": getattr(evidence, "summary", ""),
            "citations": list(getattr(evidence, "citations", []) or []),
            "resolution_chain": list(getattr(evidence, "resolution_chain", []) or []),
            "flow_chain": list(getattr(evidence, "flow_chain", []) or []),
            "unresolved_hops": list(getattr(evidence, "unresolved_hops", []) or []),
        },
    )

    if not bool(getattr(evidence, "supported", False)):
        summary = str(getattr(evidence, "summary", "") or "").strip()
        unresolved = list(getattr(evidence, "unresolved_hops", []) or [])
        if summary:
            sections.append(f"[ANALYZER_FALLBACK]\n{summary}")
        _append_labeled_lines(sections, "ANALYZER_UNRESOLVED", unresolved)
        return False, False, [], unresolved[: C.MAX_CITATIONS]

    summary = str(getattr(evidence, "summary", "") or "").strip()
    citations = list(getattr(evidence, "citations", []) or [])
    resolution_chain = list(getattr(evidence, "resolution_chain", []) or [])
    flow_chain = list(getattr(evidence, "flow_chain", []) or [])
    unresolved = list(getattr(evidence, "unresolved_hops", []) or [])
    fallback_targets = list(getattr(evidence, "fallback_targets", []) or [])
    extra_sections = list(getattr(evidence, "sections", []) or [])

    if summary:
        sections.append(f"[ANALYZER_SUMMARY]\n{summary}")
    labeled_lists = [
        ("ANALYZER_CITATIONS", citations),
        ("ANALYZER_RESOLUTION_CHAIN", resolution_chain),
        ("ANALYZER_FLOW_CHAIN", flow_chain),
        ("ANALYZER_UNRESOLVED", unresolved),
        ("ANALYZER_FALLBACK_TARGETS", fallback_targets),
        ("ANALYZER_SECTIONS", extra_sections),
    ]
    for label, lines in labeled_lists:
        _append_labeled_lines(sections, label, lines)

    has_citations = bool(citations)
    return (
        True,
        has_citations,
        fallback_targets[: C.MAX_CITATIONS],
        unresolved[: C.MAX_CITATIONS],
    )


def _collect_targeted_recovery_sections(
    state: TriageState,
    sections: list[str],
    *,
    tool_runner,
    file_path: str,
    fallback_targets: list[str],
    analyzer_unresolved_hops: list[str],
    max_sections: int,
) -> None:
    if not fallback_targets:
        return
    fallback_paths = _build_targeted_recovery_paths(
        file_path=file_path,
        analyzer_unresolved_hops=analyzer_unresolved_hops,
    )
    root_scope_symbols = _extract_cross_boundary_symbols(analyzer_unresolved_hops)
    targets = [t for t in fallback_targets if t][: C.MAX_TARGETS]
    for target in targets:
        if len(sections) >= max_sections:
            break
        pattern = _token_pattern(target)
        for path in fallback_paths:
            if path == "." and root_scope_symbols and target not in root_scope_symbols:
                continue
            grep_max_lines = (
                C.TARGETED_ROOT_GREP_MAX_LINES
                if path == "."
                else C.TARGETED_GREP_MAX_LINES
            )
            grep_max_chars = (
                C.TARGETED_ROOT_GREP_MAX_CHARS
                if path == "."
                else C.TARGETED_GREP_MAX_CHARS
            )
            output = _safe_tool_capture(
                state,
                sections,
                tool_name="grep",
                tool_args={"pattern": pattern, "path": path, "mode": "targeted"},
                section_label=f"TARGETED_GREP {target} IN {path}",
                error_label=f"TARGETED_GREP_ERROR {target}",
                max_lines=grep_max_lines,
                max_chars=grep_max_chars,
                append_error_section=False,
                invoke=lambda gp=path: tool_runner.grep(pattern, gp),
            )
            if output is None:
                continue
            hits = _parse_grep_hits(output, max_hits=C.MAX_TARGETED_HITS)
            for hit_path, hit_line in hits[: C.MAX_TARGETED_CONTEXT_HITS]:
                if len(sections) >= max_sections:
                    break
                start = max(1, hit_line - C.TARGETED_HIT_RADIUS)
                end = hit_line + C.TARGETED_HIT_RADIUS
                _safe_tool_capture(
                    state,
                    sections,
                    tool_name="sed",
                    tool_args={
                        "path": hit_path,
                        "start_line": start,
                        "end_line": end,
                        "mode": "targeted",
                    },
                    section_label=f"TARGETED_HIT_CONTEXT {hit_path}:{start}-{end}",
                    max_lines=C.TARGETED_HIT_CONTEXT_MAX_LINES,
                    max_chars=C.TARGETED_HIT_CONTEXT_MAX_CHARS,
                    append_error_section=False,
                    invoke=lambda p=hit_path, s=start, e=end: tool_runner.sed(p, s, e),
                )
            if len(sections) >= max_sections:
                break


def _build_targeted_recovery_paths(
    *,
    file_path: str,
    analyzer_unresolved_hops: list[str],
) -> list[str]:
    paths = _build_fallback_paths(file_path)
    if _has_cross_boundary_unresolved_hops(analyzer_unresolved_hops):
        if "." in paths:
            paths = [p for p in paths if p != "."]
        paths = ["."] + paths
    return paths


def _has_cross_boundary_unresolved_hops(unresolved_hops: list[str]) -> bool:
    if not unresolved_hops:
        return False
    for hop in unresolved_hops:
        if is_cross_boundary_unresolved_hop(hop):
            return True
    return False


def _extract_cross_boundary_symbols(unresolved_hops: list[str]) -> set[str]:
    symbols: set[str] = set()
    for hop in unresolved_hops:
        text = str(hop or "").strip()
        if not is_cross_boundary_unresolved_hop(text):
            continue
        if ":" not in text:
            continue
        candidate = text.split(":", 1)[1].strip()
        if not candidate:
            continue
        if ":" in candidate:
            candidate = candidate.split(":", 1)[0].strip()
        if candidate:
            symbols.add(candidate)
    return symbols


def _merge_terms_with_fallback_targets(
    *,
    terms: list[str],
    fallback_targets: list[str],
    limit: int = C.MERGED_TERMS_LIMIT,
) -> list[str]:
    if not fallback_targets:
        return terms
    boosted_terms = [t for t in fallback_targets if t][: C.ANALYZER_MAX_FALLBACK_TERMS]
    merged = boosted_terms + terms
    dedup_terms: list[str] = []
    seen_terms: set[str] = set()
    for term in merged:
        if not term or term in seen_terms:
            continue
        seen_terms.add(term)
        dedup_terms.append(term)
        if len(dedup_terms) >= limit:
            break
    return dedup_terms


def _emit_hybrid_fallback_policy(
    state: TriageState,
    *,
    analyzer_supported: bool,
    analyzer_has_citations: bool,
    analyzer_fallback_targets: list[str],
) -> None:
    if not analyzer_supported:
        return
    has_targets = bool(analyzer_fallback_targets)
    policy = "hybrid_baseline_plus_targeted" if has_targets else "hybrid_baseline"
    reason = (
        "analyzer_supported_with_unresolved_or_explicit_targets"
        if has_targets
        else "analyzer_supported"
    )
    _emit_debug(
        state,
        "tool_call",
        tool_name="triage_fallback_policy",
        tool_args={"policy": policy, "reason": reason},
        tool_output={
            "analyzer_supported": analyzer_supported,
            "analyzer_has_citations": analyzer_has_citations,
            "fallback_targets": analyzer_fallback_targets if has_targets else [],
        },
    )


def _finalize_evidence_pack_state(
    state: TriageState, sections: list[str]
) -> TriageState:
    evidence_pack = "\n\n".join(sections)
    if len(evidence_pack) > C.EVIDENCE_PACK_MAX_CHARS:
        evidence_pack = evidence_pack[: C.EVIDENCE_PACK_MAX_CHARS] + "\n...[truncated]"
    new_state: TriageState = dict(state)
    new_state["evidence_pack"] = evidence_pack
    return new_state
