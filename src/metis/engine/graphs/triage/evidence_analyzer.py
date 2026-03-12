# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.analysis.base import AnalyzerRequest

from . import constants as C
from .debug import _emit_debug
from ..types import TriageState


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

    supported = bool(getattr(evidence, "supported", False))
    summary = str(getattr(evidence, "summary", "") or "").strip()
    citations = list(getattr(evidence, "citations", []) or [])
    resolution_chain = list(getattr(evidence, "resolution_chain", []) or [])
    flow_chain = list(getattr(evidence, "flow_chain", []) or [])
    unresolved = list(getattr(evidence, "unresolved_hops", []) or [])
    fallback_targets = list(getattr(evidence, "fallback_targets", []) or [])

    if summary:
        label = "ANALYZER_SUMMARY" if supported else "ANALYZER_FALLBACK"
        sections.append(f"[{label}]\n{summary}")

    _append_labeled_lines(sections, "ANALYZER_CITATIONS", citations)
    _append_labeled_lines(sections, "ANALYZER_RESOLUTION_CHAIN", resolution_chain)
    _append_labeled_lines(sections, "ANALYZER_FLOW_CHAIN", flow_chain)
    _append_labeled_lines(sections, "ANALYZER_UNRESOLVED", unresolved)
    _append_labeled_lines(sections, "ANALYZER_FALLBACK_TARGETS", fallback_targets)

    return (
        supported,
        bool(citations),
        fallback_targets[: C.MAX_CITATIONS],
        unresolved[: C.MAX_CITATIONS],
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
