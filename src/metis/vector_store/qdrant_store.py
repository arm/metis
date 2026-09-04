# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from contextlib import suppress

from llama_index.core import StorageContext
from llama_index.vector_stores.qdrant import QdrantVectorStore
from qdrant_client import QdrantClient
from qdrant_client.models import Distance
from qdrant_client.models import VectorParams

from metis.vector_store.llama_index_backend import LlamaIndexVectorBackend


class QdrantStore(LlamaIndexVectorBackend):
    def __init__(
        self,
        *,
        url: str,
        api_key: str | None,
        collection_prefix: str,
        embed_dim: int,
        embed_model_code,
        embed_model_docs,
        query_config=None,
    ) -> None:
        self.url = url
        self.api_key = api_key
        self.collection_prefix = collection_prefix
        self.embed_dim = embed_dim
        self.embed_model_code = embed_model_code
        self.embed_model_docs = embed_model_docs
        self.query_config = query_config or {}
        self._client: QdrantClient | None = None

    def init(self) -> None:
        if self._client is not None:
            return
        client = QdrantClient(url=self.url, api_key=self.api_key)
        try:
            components = self._build_store_components(client)
        except Exception:
            with suppress(Exception):
                client.close()
            raise

        (
            self.vector_store_code,
            self.vector_store_docs,
            self.storage_context_code,
            self.storage_context_docs,
        ) = components
        self._client = client

    def _build_store_components(self, client: QdrantClient):
        for kind in ("code", "docs"):
            name = f"{self.collection_prefix}_{kind}"
            if client.collection_exists(name):
                continue

            client.create_collection(
                collection_name=name,
                vectors_config=VectorParams(
                    size=self.embed_dim,
                    distance=Distance.COSINE,
                ),
            )

        stores = tuple(
            QdrantVectorStore(
                client=client,
                collection_name=f"{self.collection_prefix}_{kind}",
            )
            for kind in ("code", "docs")
        )
        contexts = tuple(
            StorageContext.from_defaults(vector_store=store) for store in stores
        )
        return *stores, *contexts

    def reset_index(self) -> None:
        self.init()
        assert self._client is not None
        for kind in ("code", "docs"):
            name = f"{self.collection_prefix}_{kind}"
            if self._client.collection_exists(name):
                self._client.delete_collection(name)
        (
            self.vector_store_code,
            self.vector_store_docs,
            self.storage_context_code,
            self.storage_context_docs,
        ) = self._build_store_components(self._client)

    def close(self) -> None:
        if self._client is not None:
            with suppress(Exception):
                self._client.close()
        self._client = None
