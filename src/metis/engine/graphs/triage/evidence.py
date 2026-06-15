# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re

from . import constants as C
from ..types import TriageState
from .evidence_text import (
    _extract_call_like_identifiers,
    _extract_terms,
)
from .evidence_tools import (
    _collect_file_context,
    _collect_hit_context_sections,
    _collect_use_site_sections,
    _gather_symbol_definition_hits,
)
from .debug import _emit_debug
from .obligations import (
    OBLIGATION_USE_SITE,
    compute_obligation_coverage,
    derive_obligations,
)


_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def _extract_symbol_candidates(*texts: str, limit: int = 12) -> list[str]:
    symbols: list[str] = []
    seen: set[str] = set()
    for text in texts:
        for token in _IDENT_RE.findall(text or ""):
            if token in seen:
                continue
            seen.add(token)
            symbols.append(token)
            if len(symbols) >= limit:
                return symbols
    return symbols


def _enforce_section_limit(sections: list[str], *, max_sections: int) -> list[str]:
    if max_sections <= 0:
        return []
    if len(sections) <= max_sections:
        return sections
    return sections[:max_sections]


def _pre_use_site_section_limit(max_sections: int) -> int:
    if max_sections <= 0:
        return 0
    reserve = min(C.USE_SITE_RETRY_SECTION_RESERVE, max_sections // 4)
    return max(1, max_sections - reserve)


def _derive_line_symbols(
    state: TriageState,
    *,
    exact_line_context: str,
    is_metis_source: bool,
    max_symbol_terms: int,
) -> list[str]:
    snippet_text = state.get("finding_snippet", "") or ""
    explanation_text = state.get("finding_explanation", "") if is_metis_source else ""
    term_source = " ".join(
        [
            state.get("finding_message", "") or "",
            snippet_text,
            explanation_text or "",
        ]
    )
    line_terms = _extract_call_like_identifiers(
        "\n".join([exact_line_context, snippet_text]),
        limit=12,
    )
    snippet_candidates = _extract_symbol_candidates(snippet_text, limit=12)
    exact_candidates = _extract_symbol_candidates(exact_line_context, limit=12)
    prose_terms = _extract_terms(term_source, limit=12)

    out: list[str] = []
    seen: set[str] = set()
    for term in line_terms + snippet_candidates + prose_terms + exact_candidates:
        if not term or term in seen:
            continue
        if len(term) > 64:
            continue
        if not _is_probe_term(term):
            continue
        seen.add(term)
        out.append(term)
        if len(out) >= max_symbol_terms:
            break
    return out


def _is_probe_term(term: str) -> bool:
    text = str(term or "").strip()
    if not text:
        return False
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]{1,127}$", text))


def _section_labels(sections: list[str]) -> list[str]:
    labels: list[str] = []
    for section in sections:
        if not str(section).startswith("["):
            continue
        raw = str(section)[1:].split("]", 1)[0].strip()
        if raw:
            labels.append(raw)
    return labels


def _finalize_evidence_pack_state(
    state: TriageState, sections: list[str]
) -> TriageState:
    evidence_pack = "\n\n".join(sections)
    if len(evidence_pack) > C.EVIDENCE_PACK_MAX_CHARS:
        evidence_pack = evidence_pack[: C.EVIDENCE_PACK_MAX_CHARS] + "\n...[truncated]"
    new_state: TriageState = dict(state)
    new_state["evidence_pack"] = evidence_pack
    return new_state


def triage_node_collect_evidence(state: TriageState, *, toolbox) -> TriageState:
    file_path = state.get("finding_file_path", "") or ""
    line = int(state.get("finding_line", 1) or 1)
    is_metis_source = bool(state.get("finding_is_metis", False))

    window_radius = (
        C.FILE_WINDOW_RADIUS_METIS if is_metis_source else C.FILE_WINDOW_RADIUS_EXTERNAL
    )
    max_symbol_terms = (
        C.MAX_SYMBOL_TERMS_METIS if is_metis_source else C.MAX_SYMBOL_TERMS_EXTERNAL
    )

    sections: list[str] = []
    max_sections = C.MAX_SECTIONS
    pre_use_site_max_sections = _pre_use_site_section_limit(max_sections)

    exact_line_context = _collect_file_context(
        state,
        sections,
        toolbox=toolbox,
        file_path=file_path,
        line=line,
        window_radius=window_radius,
    )

    if is_metis_source:
        explanation = str(state.get("finding_explanation", "") or "").strip()
        if explanation:
            sections.append(f"[METIS_EXPLANATION]\n{explanation}")

    symbols = _derive_line_symbols(
        state,
        exact_line_context=exact_line_context,
        is_metis_source=is_metis_source,
        max_symbol_terms=max_symbol_terms,
    )

    (
        followup_hits,
        definition_hints,
        unresolved_symbols,
    ) = _gather_symbol_definition_hits(
        state,
        sections,
        toolbox=toolbox,
        symbols=symbols,
        file_path=file_path,
        max_followup_hits=C.DEFAULT_MAX_FOLLOWUP_HITS,
        max_sections=pre_use_site_max_sections,
    )

    if definition_hints:
        hint_section = "[SYMBOL_RESOLUTION_HINTS]\n" + "\n".join(
            sorted(definition_hints, key=lambda s: s.lower())[: C.MAX_CITATIONS]
        )
        sections.insert(0, hint_section)

    _collect_hit_context_sections(
        state,
        sections,
        toolbox=toolbox,
        followup_hits=followup_hits,
        max_sections=pre_use_site_max_sections,
    )

    sections = _enforce_section_limit(sections, max_sections=pre_use_site_max_sections)

    symbol_unresolved_hops = [
        f"SYMBOL_DEFINITION_UNRESOLVED:{symbol}" for symbol in unresolved_symbols
    ]

    obligations = derive_obligations(
        analyzer_supported=False,
        analyzer_unresolved_hops=symbol_unresolved_hops,
    )
    obligation_coverage, obligation_missing = compute_obligation_coverage(
        obligations=obligations,
        sections=sections,
        unresolved_hops=symbol_unresolved_hops,
        has_definition_hints=bool(definition_hints),
    )
    if OBLIGATION_USE_SITE in obligation_missing:
        _collect_use_site_sections(
            state,
            sections,
            toolbox=toolbox,
            symbols=symbols,
            file_path=file_path,
            line=line,
            max_sections=max_sections,
        )
        sections = _enforce_section_limit(sections, max_sections=max_sections)
        obligation_coverage, obligation_missing = compute_obligation_coverage(
            obligations=obligations,
            sections=sections,
            unresolved_hops=symbol_unresolved_hops,
            has_definition_hints=bool(definition_hints),
        )

    evidence_gate_missing = [
        f"OBLIGATION_MISSING:{name}" for name in obligation_missing
    ]
    state["evidence_obligations"] = obligations
    state["obligation_coverage"] = obligation_coverage
    state["evidence_gate_missing"] = evidence_gate_missing
    _emit_debug(
        state,
        "evidence_gate",
        obligations=obligations,
        obligation_coverage=obligation_coverage,
        missing=evidence_gate_missing,
        section_labels=_section_labels(sections),
    )

    return _finalize_evidence_pack_state(state, sections)
