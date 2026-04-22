# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.retrieval_support import retrieve_context_deterministic


class RetrievalToolRunner:
    def __init__(self, *, max_chars: int = 16000):
        self.max_chars = max_chars

    def rag_search(
        self,
        query: str,
        *,
        retriever_code=None,
        retriever_docs=None,
    ) -> str:
        normalized_query = str(query or "").strip()
        if not normalized_query:
            return "[RAG_SEARCH]\nEmpty query."

        code_budget = max(600, int(self.max_chars * 0.7))
        docs_budget = max(400, self.max_chars - code_budget)
        code = retrieve_context_deterministic(
            retriever_code,
            normalized_query,
            max_chars=code_budget,
        )
        docs = retrieve_context_deterministic(
            retriever_docs,
            normalized_query,
            max_chars=docs_budget,
        )

        sections: list[str] = ["[RAG_QUERY]", normalized_query, ""]
        if retriever_code is None:
            sections.extend(["[CODE_RAG_STATUS]", "unavailable", ""])
        else:
            sections.extend(["[CODE_RAG]", code or "<none>", ""])

        if retriever_docs is None:
            sections.extend(["[DOCS_RAG_STATUS]", "unavailable", ""])
        else:
            sections.extend(["[DOCS_RAG]", docs or "<none>", ""])

        if retriever_code is None and retriever_docs is None:
            sections.extend(
                [
                    "[RAG_SEARCH_STATUS]",
                    "retrieval unavailable; continuing without indexed context",
                ]
            )

        text = "\n".join(sections).strip()
        if len(text) <= self.max_chars:
            return text
        return text[: self.max_chars] + "\n...[truncated]"
