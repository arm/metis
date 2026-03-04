# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os

from metis.engine.analysis.c_family_helpers import extract_c_family_seed_symbols

from ..types import TriageState
from .retrieval import _extract_symbol_candidates
from .evidence_text import (
    _extract_call_like_identifiers,
    _extract_referenced_paths,
    _extract_terms,
    _build_related_paths,
)
from .evidence_tools import (
    _collect_file_context,
    _gather_symbol_hits,
    _collect_hit_context_sections,
)
from .evidence_analyzer import (
    _collect_analyzer_sections,
    _collect_targeted_recovery_sections,
    _merge_terms_with_fallback_targets,
    _emit_hybrid_fallback_policy,
    _finalize_evidence_pack_state,
)


def _derive_search_terms(
    state: TriageState,
    *,
    file_path: str,
    line_context: str,
    file_head_context: str,
    exact_line_context: str,
) -> tuple[list[str], list[str]]:
    term_source = " ".join(
        [
            state.get("finding_message", "") or "",
            state.get("finding_snippet", "") or "",
        ]
    )
    finding_terms = _extract_terms(term_source, limit=12)
    context_terms = _extract_call_like_identifiers(
        "\n".join([exact_line_context, line_context]), limit=12
    )
    snippet_symbols = _extract_symbol_candidates(
        exact_line_context,
        state.get("finding_snippet", "") or "",
        state.get("finding_rule_id", "") or "",
        os.path.basename(file_path or ""),
        limit=12,
    )
    refs = _extract_referenced_paths(
        "\n".join(
            [
                line_context,
                file_head_context,
                state.get("finding_snippet", "") or "",
                state.get("finding_message", "") or "",
            ]
        ),
        limit=24,
    )
    related_paths = _build_related_paths(file_path, refs, limit=12)

    terms = []
    seen_terms = set()
    # Prioritize symbols found in code context over prose terms from finding text.
    prioritized_terms = context_terms + snippet_symbols + finding_terms
    for term in prioritized_terms:
        if term in seen_terms:
            continue
        if len(term) > 64:
            continue
        seen_terms.add(term)
        terms.append(term)
        if len(terms) >= 3:
            break

    context_term_set = set(context_terms)
    # Keep at least one symbol from code context when available.
    if context_terms and not any(t in context_term_set for t in terms):
        ctx = context_terms[0]
        if len(terms) >= 3:
            terms[-1] = ctx
        else:
            terms.append(ctx)
    return terms, related_paths


def triage_node_collect_evidence(state: TriageState, *, tool_runner) -> TriageState:
    file_path = state.get("finding_file_path", "") or ""
    line = int(state.get("finding_line", 1) or 1)
    sections: list[str] = []
    max_sections = 28
    analyzer_symbols: list[str] = []
    ext = os.path.splitext(file_path or "")[1].lower()
    if ext in {".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".hxx", ".cxx"}:
        analyzer_symbols = extract_c_family_seed_symbols(
            state.get("finding_snippet", "") or "",
            state.get("finding_rule_id", "") or "",
            file_path or "",
            limit=20,
        )
    (
        analyzer_supported,
        analyzer_has_citations,
        analyzer_fallback_targets,
        analyzer_unresolved_hops,
    ) = _collect_analyzer_sections(
        state,
        sections,
        file_path=file_path,
        line=line,
        candidate_symbols=analyzer_symbols,
        max_sections=max_sections,
    )
    line_context, file_head_context, exact_line_context = _collect_file_context(
        state,
        sections,
        tool_runner=tool_runner,
        file_path=file_path,
        line=line,
    )
    terms, related_paths = _derive_search_terms(
        state,
        file_path=file_path,
        line_context=line_context,
        file_head_context=file_head_context,
        exact_line_context=exact_line_context,
    )
    terms = _merge_terms_with_fallback_targets(
        terms=terms,
        fallback_targets=analyzer_fallback_targets,
    )
    _emit_hybrid_fallback_policy(
        state,
        analyzer_supported=analyzer_supported,
        analyzer_has_citations=analyzer_has_citations,
        analyzer_fallback_targets=analyzer_fallback_targets,
    )
    if analyzer_supported and analyzer_fallback_targets:
        _collect_targeted_recovery_sections(
            state,
            sections,
            tool_runner=tool_runner,
            file_path=file_path,
            fallback_targets=analyzer_fallback_targets,
            analyzer_unresolved_hops=analyzer_unresolved_hops,
            max_sections=max_sections,
        )
    max_followup_hits = 12
    if analyzer_supported:
        max_followup_hits = 8
    followup_hits, definition_hints = _gather_symbol_hits(
        state,
        sections,
        tool_runner=tool_runner,
        terms=terms,
        file_path=file_path,
        related_paths=related_paths,
        max_followup_hits=max_followup_hits,
        max_sections=max_sections,
    )

    if definition_hints:
        sections.insert(
            0,
            "[SYMBOL_RESOLUTION_HINTS]\n"
            + "\n".join(sorted(definition_hints, key=lambda s: s.lower())[:12]),
        )

    _collect_hit_context_sections(
        state,
        sections,
        tool_runner=tool_runner,
        followup_hits=followup_hits,
        max_followup_hits=max_followup_hits,
        max_sections=max_sections,
    )

    return _finalize_evidence_pack_state(state, sections)
