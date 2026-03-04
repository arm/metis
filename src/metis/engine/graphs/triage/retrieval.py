# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import hashlib

from metis.engine.analysis.c_family_helpers import extract_code_like_symbols

from .debug import _emit_debug
from ..types import TriageState
from ..utils import synthesize_context


def _normalize_doc(doc):
    content = str(getattr(doc, "page_content", "") or "")
    meta = getattr(doc, "metadata", {}) or {}
    source = str(
        meta.get("file_path") or meta.get("source") or meta.get("doc_id") or ""
    )
    raw_line = meta.get("line") or meta.get("start_line") or meta.get("line_number")
    try:
        line = int(raw_line)
    except Exception:
        line = 0
    return source, line, content


def _retrieve_context_deterministic(
    retriever, query: str, max_chars: int = 14000
) -> str:
    try:
        docs = retriever.get_relevant_documents(query) or []
    except Exception:
        return ""

    normalized = [_normalize_doc(doc) for doc in docs]
    dedup = {}
    for source, line, content in normalized:
        digest = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
        key = (source, line, digest)
        dedup[key] = (source, line, content)

    ordered = sorted(
        dedup.values(),
        key=lambda x: (
            x[0].lower(),
            x[1],
            hashlib.sha256(x[2].encode("utf-8", errors="ignore")).hexdigest(),
        ),
    )

    parts: list[str] = []
    used = 0
    for source, line, content in ordered:
        label = source if source else "<unknown>"
        line_label = f":{line}" if line > 0 else ""
        section = f"[{label}{line_label}]\n{content.strip()}\n"
        if not section.strip():
            continue
        remaining = max_chars - used
        if remaining <= 0:
            break
        if len(section) > remaining:
            parts.append(section[:remaining] + "\n...[truncated]")
            used = max_chars
            break
        parts.append(section)
        used += len(section)

    return "\n".join(parts).strip()


def _extract_symbol_candidates(
    *texts: str,
    limit: int = 12,
) -> list[str]:
    return extract_code_like_symbols(*texts, limit=limit)


def _build_retrieval_query(state: TriageState) -> str:
    symbols = _extract_symbol_candidates(
        state.get("finding_rule_id", "") or "",
        state.get("finding_file_path", "") or "",
        state.get("finding_snippet", "") or "",
        limit=10,
    )
    term_line = ", ".join(symbols) if symbols else "<none>"
    return (
        "Triage using deterministic evidence extraction and symbol resolution.\n"
        "Reported line may be inaccurate. Retrieve likely definition files, aliases, and call sites "
        "related to the finding from the repository root.\n\n"
        f"Rule: {state.get('finding_rule_id', '')}\n"
        f"File: {state.get('finding_file_path', '')}\n"
        f"Reported line: {state.get('finding_line', 1)}\n"
        f"Finding: {state.get('finding_message', '')}\n"
        f"Snippet: {state.get('finding_snippet', '')}\n"
        f"Candidate symbols: {term_line}\n"
        "Question: What concrete evidence supports or contradicts this finding, and which definition chain resolves the reported behavior?"
    )


def triage_node_retrieve(state: TriageState) -> TriageState:
    query = _build_retrieval_query(state)
    code = _retrieve_context_deterministic(state["retriever_code"], query)
    docs = _retrieve_context_deterministic(state["retriever_docs"], query)
    context = synthesize_context(code, docs)
    _emit_debug(
        state,
        "retrieval",
        query=query,
        code_context=code,
        docs_context=docs,
        context=context,
    )
    new_state: TriageState = dict(state)
    new_state["context"] = context
    return new_state
