# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
from threading import RLock

from chromadb import PersistentClient
from chromadb.config import Settings
from llama_index.core import StorageContext
from llama_index.vector_stores.chroma import ChromaVectorStore

from metis.exceptions import RetrieverInitError, VectorStoreInitError
from metis.vector_store.base import BaseVectorStore
from metis.vector_store.retrievers import (
    ChromaCollectionRetriever,
    QueryAnswerRetriever,
)

logger = logging.getLogger(__name__)


class ChromaStore(BaseVectorStore):
    def __init__(self, persist_dir, embed_model_code, embed_model_docs, query_config):
        self.persist_dir = persist_dir
        self.embed_model_code = embed_model_code
        self.embed_model_docs = embed_model_docs
        self.query_config = query_config
        self._client = None
        self._initialized = False
        self._init_lock = RLock()

    def init(self):
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            try:
                settings = Settings(anonymized_telemetry=False)
                # Ensure this local store always uses Chroma's embedded backend.
                settings.chroma_api_impl = "chromadb.api.rust.RustBindingsAPI"
                client = PersistentClient(
                    path=self.persist_dir,
                    settings=settings,
                )
                code_collection = client.get_or_create_collection("code")
                docs_collection = client.get_or_create_collection("docs")
                self._set_collections(code_collection, docs_collection)
                self._client = client
                self._initialized = True
                logger.info("Chroma vector components initialized.")

            except Exception as e:
                logger.error(f"Error initializing ChromaStore: {e}")
                raise VectorStoreInitError()

    def get_retrievers(
        self,
        llm_provider,
        similarity_top_k=None,
        callback_manager=None,
        callbacks=None,
    ):
        try:
            top_k = similarity_top_k or self.query_config.get("similarity_top_k", 5)
            chat_model_kwargs = {"response_format": None}
            if callbacks:
                chat_model_kwargs["callbacks"] = callbacks
            retriever_code = QueryAnswerRetriever(
                ChromaCollectionRetriever(
                    self.collection_code,
                    self.embed_model_code,
                    k=top_k,
                ),
                llm_provider,
                chat_model_kwargs=chat_model_kwargs,
            )
            retriever_docs = QueryAnswerRetriever(
                ChromaCollectionRetriever(
                    self.collection_docs,
                    self.embed_model_docs,
                    k=top_k,
                ),
                llm_provider,
                chat_model_kwargs=chat_model_kwargs,
            )
            return (retriever_code, retriever_docs)
        except Exception as e:
            logger.error(f"Error creating Chroma retrievers: {e}")
            raise RetrieverInitError()

    def _set_collections(self, code_collection, docs_collection):
        self.collection_code = code_collection
        self.collection_docs = docs_collection
        self.vector_store_code = ChromaVectorStore(
            chroma_collection=code_collection,
            embed_model=self.embed_model_code,
        )
        self.vector_store_docs = ChromaVectorStore(
            chroma_collection=docs_collection,
            embed_model=self.embed_model_docs,
        )
        self.storage_context_code = StorageContext.from_defaults(
            vector_store=self.vector_store_code
        )
        self.storage_context_docs = StorageContext.from_defaults(
            vector_store=self.vector_store_docs
        )

    def reset_index(self):
        if not self._initialized:
            self.init()
        assert self._client is not None
        for name in ("code", "docs"):
            try:
                self._client.delete_collection(name)
            except Exception:
                logger.debug("Chroma collection '%s' did not exist during reset", name)
        code_collection = self._client.get_or_create_collection("code")
        docs_collection = self._client.get_or_create_collection("docs")
        self._set_collections(code_collection, docs_collection)
        logger.info("Chroma vector collections reset.")

    def get_storage_contexts(self):
        return self.storage_context_code, self.storage_context_docs

    def close(self):
        client = self._client
        if client is not None:
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Error closing ChromaStore: {e}")
        self._client = None
        self._initialized = False
        for attr in (
            "vector_store_code",
            "vector_store_docs",
            "collection_code",
            "collection_docs",
            "storage_context_code",
            "storage_context_docs",
        ):
            if hasattr(self, attr):
                delattr(self, attr)
