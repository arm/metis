# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os

from metis.engine.analysis.c_family_macro import (
    is_c_family_file_path,
    is_c_macro_like_symbol,
)
from metis.engine.analysis.c_family_helpers import extract_c_family_seed_symbols

from . import constants as C
from ..types import TriageState
from .retrieval import _extract_symbol_candidates
from .evidence_text import (
    _extract_call_like_identifiers,
    _extract_terms,
)
from .evidence_tools import (
    _collect_file_context,
    _collect_hit_context_sections,
    _collect_macro_definition_sections,
    _collect_treesitter_scope_symbols,
    _gather_symbol_definition_hits,
)
from .evidence_analyzer import (
    _collect_analyzer_sections,
    _finalize_evidence_pack_state,
)
from .obligations import (
    compute_obligation_coverage,
    derive_obligations,
)


def _enforce_section_limit(
    sections: list[str], *, max_sections: int
) -> tuple[list[str], int]:
    if max_sections <= 0:
        return [], len(sections)
    if len(sections) <= max_sections:
        return sections, 0
    dropped = sections[max_sections:]
    return sections[:max_sections], len(dropped)


def _derive_line_symbols(
    state: TriageState,
    *,
    file_path: str,
    exact_line_context: str,
    treesitter_scope_symbols: list[str],
    is_metis_source: bool,
    max_symbol_terms: int,
) -> list[str]:
    explanation_text = state.get("finding_explanation", "") if is_metis_source else ""
    term_source = " ".join(
        [
            state.get("finding_message", "") or "",
            state.get("finding_snippet", "") or "",
            explanation_text or "",
        ]
    )
    line_terms = _extract_call_like_identifiers(
        "\n".join([exact_line_context, state.get("finding_snippet", "") or ""]),
        limit=12,
    )
    symbol_candidates = _extract_symbol_candidates(
        exact_line_context,
        " ".join(treesitter_scope_symbols),
        state.get("finding_snippet", "") or "",
        state.get("finding_rule_id", "") or "",
        os.path.basename(file_path or ""),
        limit=12,
    )
    prose_terms = _extract_terms(term_source, limit=12)

    out: list[str] = []
    seen: set[str] = set()
    for term in line_terms + treesitter_scope_symbols + symbol_candidates + prose_terms:
        if not term or term in seen:
            continue
        if len(term) > 64:
            continue
        seen.add(term)
        out.append(term)
        if len(out) >= max_symbol_terms:
            break
    return out


def _filter_resolved_macro_unresolved_hops(
    unresolved_hops: list[str], resolved_macros: dict[str, str]
) -> list[str]:
    if not unresolved_hops or not resolved_macros:
        return unresolved_hops
    resolved_names = {
        str(k or "").strip() for k in resolved_macros if str(k or "").strip()
    }
    if not resolved_names:
        return unresolved_hops
    kept: list[str] = []
    for hop in unresolved_hops:
        text = str(hop or "").strip()
        if not text:
            continue
        drop = False
        for macro in resolved_names:
            if text == f"MACRO_SEMANTICS_UNRESOLVED:{macro}":
                drop = True
                break
            if text.startswith(f"MACRO_SEMANTICS_WEAK:{macro}:"):
                drop = True
                break
        if not drop:
            kept.append(text)
    return kept


def triage_node_collect_evidence(state: TriageState, *, toolbox) -> TriageState:
    file_path = state.get("finding_file_path", "") or ""
    line = int(state.get("finding_line", 1) or 1)
    is_metis_source = bool(state.get("finding_is_metis", False))
    scope_mode = "line_local"

    window_radius = (
        C.FILE_WINDOW_RADIUS_METIS if is_metis_source else C.FILE_WINDOW_RADIUS_EXTERNAL
    )
    max_symbol_terms = (
        C.MAX_SYMBOL_TERMS_METIS if is_metis_source else C.MAX_SYMBOL_TERMS_EXTERNAL
    )

    sections: list[str] = []
    max_sections = C.MAX_SECTIONS

    analyzer_symbols: list[str] = []
    ext = os.path.splitext(file_path or "")[1].lower()
    if ext in {".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".hxx", ".cxx"}:
        analyzer_symbols = extract_c_family_seed_symbols(
            state.get("finding_snippet", "") or "",
            state.get("finding_rule_id", "") or "",
            file_path or "",
            limit=C.ANALYZER_SEED_SYMBOL_LIMIT,
        )

    (
        analyzer_supported,
        _analyzer_has_citations,
        _analyzer_fallback_targets,
        analyzer_unresolved_hops,
    ) = _collect_analyzer_sections(
        state,
        sections,
        file_path=file_path,
        line=line,
        candidate_symbols=analyzer_symbols,
        max_sections=max_sections,
    )

    exact_line_context = _collect_file_context(
        state,
        sections,
        toolbox=toolbox,
        file_path=file_path,
        line=line,
        window_radius=window_radius,
    )
    treesitter_scope_symbols, treesitter_macros = _collect_treesitter_scope_symbols(
        state,
        sections,
        file_path=file_path,
        line=line,
        max_symbols=max_symbol_terms * 3,
    )

    if is_metis_source:
        explanation = str(state.get("finding_explanation", "") or "").strip()
        if explanation:
            sections.append(f"[METIS_EXPLANATION]\n{explanation}")

    symbols = _derive_line_symbols(
        state,
        file_path=file_path,
        exact_line_context=exact_line_context,
        treesitter_scope_symbols=treesitter_scope_symbols,
        is_metis_source=is_metis_source,
        max_symbol_terms=max_symbol_terms,
    )
    macro_candidates = (
        list(treesitter_macros) if is_c_family_file_path(file_path) else []
    )
    if is_c_family_file_path(file_path) and not macro_candidates:
        for symbol in symbols:
            text = str(symbol or "").strip()
            if not text:
                continue
            if not is_c_macro_like_symbol(text):
                continue
            if text not in macro_candidates:
                macro_candidates.append(text)

    unresolved_macros, resolved_macros = _collect_macro_definition_sections(
        state,
        sections,
        toolbox=toolbox,
        file_path=file_path,
        macro_names=macro_candidates,
        max_sections=max_sections,
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
        max_sections=max_sections,
        scope_mode=scope_mode,
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
        max_followup_hits=C.DEFAULT_MAX_FOLLOWUP_HITS,
        max_sections=max_sections,
    )

    sections, _dropped_count = _enforce_section_limit(
        sections, max_sections=max_sections
    )

    symbol_unresolved_hops = [
        f"SYMBOL_DEFINITION_UNRESOLVED:{symbol}" for symbol in unresolved_symbols
    ]
    macro_unresolved_hops = [
        f"MACRO_DEFINITION_UNRESOLVED:{name}" for name in unresolved_macros
    ]
    analyzer_unresolved_hops = _filter_resolved_macro_unresolved_hops(
        analyzer_unresolved_hops,
        resolved_macros,
    )
    all_unresolved_hops = (
        list(analyzer_unresolved_hops) + symbol_unresolved_hops + macro_unresolved_hops
    )

    obligations = derive_obligations(
        analyzer_supported=analyzer_supported,
        analyzer_unresolved_hops=all_unresolved_hops,
    )
    obligation_coverage, obligation_missing = compute_obligation_coverage(
        obligations=obligations,
        sections=sections,
        unresolved_hops=all_unresolved_hops,
        has_definition_hints=bool(definition_hints),
    )

    evidence_gate_missing = [
        f"OBLIGATION_MISSING:{name}" for name in obligation_missing
    ]
    state["evidence_obligations"] = obligations
    state["obligation_coverage"] = obligation_coverage
    state["evidence_gate_missing"] = evidence_gate_missing

    return _finalize_evidence_pack_state(state, sections)
