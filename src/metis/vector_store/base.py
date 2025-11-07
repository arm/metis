# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod


class BaseVectorStore(ABC):
    @abstractmethod
    def init(self):
        """Initialize vector storage components (e.g., vector store and storage context)."""
        pass

    @abstractmethod
    def get_query_engines(self, llm_provider, similarity_top_k, response_mode):
        """Return tuple of LangChain-style retrievers (code, docs)."""
        pass

    @abstractmethod
    def get_storage_contexts(self):
        """Return tuple of storage contexts (code, docs) for indexing."""
        pass


class _Doc:
    def __init__(self, text: str):
        self.page_content = text


class QueryEngineRetriever:
    """
    Adapter that wraps a LlamaIndex QueryEngine and exposes a
    LangChain-style retriever interface: `get_relevant_documents`.
    """

    def __init__(self, query_engine):
        self._qe = query_engine

    def _query_text(self, query: str) -> str:
        res = self._qe.query(query)
        return str(getattr(res, "response", res))

    def get_relevant_documents(self, query: str):
        return [_Doc(self._query_text(query))]
