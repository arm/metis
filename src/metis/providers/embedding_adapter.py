# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from langchain_core.embeddings import Embeddings
from llama_index.core.base.embeddings.base import BaseEmbedding, Embedding
from llama_index.core.callbacks import CallbackManager


class LangChainEmbeddingAdapter(BaseEmbedding):
    """Expose a LangChain embeddings client through LlamaIndex's embedding API."""

    _client: Embeddings

    def __init__(
        self,
        client: Embeddings,
        *,
        model_name: str,
        callback_manager: CallbackManager | None = None,
    ) -> None:
        if callback_manager is None:
            super().__init__(model_name=model_name)
        else:
            super().__init__(model_name=model_name, callback_manager=callback_manager)
        self._client = client

    def _get_query_embedding(self, query: str) -> Embedding:
        return self._client.embed_query(query)

    async def _aget_query_embedding(self, query: str) -> Embedding:
        return await self._client.aembed_query(query)

    def _get_text_embedding(self, text: str) -> Embedding:
        return self._client.embed_query(text)

    async def _aget_text_embedding(self, text: str) -> Embedding:
        return await self._client.aembed_query(text)

    def _get_text_embeddings(self, texts: list[str]) -> list[Embedding]:
        return self._client.embed_documents(texts)

    async def _aget_text_embeddings(self, texts: list[str]) -> list[Embedding]:
        return await self._client.aembed_documents(texts)
