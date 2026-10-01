# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from abc import ABC
from abc import abstractmethod


class BaseVectorStore(ABC):
    @abstractmethod
    def init(self):
        """Initialize vector storage components (e.g., vector store and storage context)."""

    @abstractmethod
    def get_retrievers(
        self,
        llm_provider,
        similarity_top_k,
        callback_manager=None,
        callbacks=None,
    ):
        """Return tuple of LangChain-style retrievers (code, docs)."""

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

    @abstractmethod
    def get_index_handles(
        self,
        *,
        embed_model_code,
        embed_model_docs,
        **embed_model_kwargs,
    ):
        """Return mutable index handles (code, docs) for patch updates."""

    def get_index_state(self) -> dict | None:
        """Return the state recorded by the last index or update, or ``None``."""
        raise NotImplementedError("This vector backend cannot record index state.")

    def set_index_state(self, state: dict) -> None:
        """Record the state of the index after a successful index or update."""
        raise NotImplementedError("This vector backend cannot record index state.")

    def close(self):
        """Best-effort resource cleanup hook for vector backends."""
        return
