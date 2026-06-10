# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod


class BaseVectorStore(ABC):
    @abstractmethod
    def init(self):
        """Initialize vector storage components (e.g., vector store and storage context)."""
        pass

    @abstractmethod
    def get_retrievers(
        self,
        llm_provider,
        similarity_top_k,
        callback_manager=None,
        callbacks=None,
    ):
        """Return tuple of LangChain-style retrievers (code, docs)."""
        pass

    @abstractmethod
    def index_nodes(
        self,
        nodes_code,
        nodes_docs,
        *,
        embed_model_code,
        embed_model_docs,
        **embed_model_kwargs,
    ):
        """Write prepared code and docs nodes to the vector backend."""
        pass

    @abstractmethod
    def get_index_handles(
        self,
        *,
        embed_model_code,
        embed_model_docs,
        **embed_model_kwargs,
    ):
        """Return mutable index handles (code, docs) for patch updates."""
        pass

    def close(self):
        """Best-effort resource cleanup hook for vector backends."""
        return None
