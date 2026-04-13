# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.analysis.c_family_helpers import extract_code_like_symbols
from metis.engine.retrieval_support import retrieve_context_deterministic

from . import constants as C
from .debug import _emit_debug
from ..types import TriageState
from ..utils import synthesize_context


def _extract_symbol_candidates(
    *texts: str,
    limit: int = 12,
) -> list[str]:
    return extract_code_like_symbols(*texts, limit=limit)


def _build_retrieval_query(state: TriageState) -> str:
    is_metis_source = bool(state.get("finding_is_metis", False))
    source_tool = str(state.get("finding_source_tool", "") or "")
    explanation = str(state.get("finding_explanation", "") or "").strip()
    symbols = _extract_symbol_candidates(
        state.get("finding_rule_id", "") or "",
        state.get("finding_file_path", "") or "",
        state.get("finding_snippet", "") or "",
        explanation,
        limit=10,
    )
    term_line = ", ".join(symbols) if symbols else "<none>"
    mode_text = (
        "Metis source: include explanation/mitigation clues for symbol and flow resolution."
        if is_metis_source
        else "External source: prioritize local line and nearby context before any broader lookup."
    )
    return (
        "Triage using deterministic evidence extraction and symbol resolution.\n"
        f"{mode_text}\n\n"
        f"SARIF source tool: {source_tool}\n"
        f"Rule: {state.get('finding_rule_id', '')}\n"
        f"File: {state.get('finding_file_path', '')}\n"
        f"Reported line: {state.get('finding_line', 1)}\n"
        f"Finding: {state.get('finding_message', '')}\n"
        f"Snippet: {state.get('finding_snippet', '')}\n"
        f"Explanation: {explanation}\n"
        f"Candidate symbols: {term_line}\n"
        "Question: What concrete evidence supports or contradicts this finding, and which definition chain resolves the reported behavior?"
    )


def triage_node_retrieve(state: TriageState, *, toolbox) -> TriageState:
    if not state.get("use_retrieval_context", True):
        disabled_state: TriageState = dict(state)
        disabled_state["context"] = ""
        return disabled_state
    query = _build_retrieval_query(state)
    if getattr(toolbox, "has", lambda _name: False)("rag_search"):
        context = toolbox.rag_search(
            query,
            retriever_code=state.get("retriever_code"),
            retriever_docs=state.get("retriever_docs"),
        )
        _emit_debug(
            state,
            "tool_call",
            tool_name="rag_search",
            tool_args={"query": query, "sources": ["code", "docs"]},
            tool_output=context,
        )
        code = docs = ""
    else:
        code = retrieve_context_deterministic(
            state.get("retriever_code"),
            query,
            max_chars=C.RETRIEVAL_CONTEXT_MAX_CHARS,
        )
        docs = retrieve_context_deterministic(
            state.get("retriever_docs"),
            query,
            max_chars=C.RETRIEVAL_CONTEXT_MAX_CHARS,
        )
        context = synthesize_context(code, docs)
    _emit_debug(
        state,
        "retrieval",
        query=query,
        code_context=code,
        docs_context=docs,
        context=context,
    )
    next_state: TriageState = dict(state)
    next_state["context"] = context
    return next_state
