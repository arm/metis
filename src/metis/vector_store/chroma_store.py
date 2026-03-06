# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.vector_stores.chroma import ChromaVectorStore
from llama_index.core import StorageContext, VectorStoreIndex
from chromadb import PersistentClient
from metis.exceptions import VectorStoreInitError, QueryEngineInitError
from metis.vector_store.base import BaseVectorStore, QueryEngineRetriever
from chromadb.config import Settings
from threading import Lock

import logging

logger = logging.getLogger(__name__)


class ChromaStore(BaseVectorStore):
    def __init__(self, persist_dir, embed_model_code, embed_model_docs, query_config):
        self.persist_dir = persist_dir
        self.embed_model_code = embed_model_code
        self.embed_model_docs = embed_model_docs
        self.query_config = query_config
        self._client = None
        self._initialized = False
        self._init_lock = Lock()

    def _detach_state(self, client=None):
        # Drop shared state under _init_lock so other threads can re-init immediately.
        detached_client = self._client if client is None else client
        self._client = None
        self._initialized = False
        for attr in (
            "vector_store_code",
            "vector_store_docs",
            "storage_context_code",
            "storage_context_docs",
        ):
            if hasattr(self, attr):
                delattr(self, attr)
        return detached_client

    def _stop_client(self, client):
        # Chroma shutdown can block; callers decide whether lock must be held.
        if client is None:
            return
        try:
            close_fn = getattr(client, "close", None)
            if callable(close_fn):
                # close() is refcount-aware for shared PersistentClient systems.
                close_fn()
                return
            stop_fn = getattr(getattr(client, "_system", None), "stop", None)
            if callable(stop_fn):
                stop_fn()
        except Exception as e:
            logger.warning(f"Error closing ChromaStore: {e}")

    def _stop_client_legacy_path_under_lock(self, client):
        # client._system.stop() is not refcount-aware on older chromadb clients.
        close_fn = getattr(client, "close", None)
        if callable(close_fn):
            return client
        self._stop_client(client)
        return None

    def init(self):
        client_to_stop = None
        init_error = None
        with self._init_lock:
            if self._initialized:
                return
            client = None
            try:
                client = PersistentClient(
                    path=self.persist_dir, settings=Settings(anonymized_telemetry=False)
                )
                code_collection = client.get_or_create_collection("code")
                docs_collection = client.get_or_create_collection("docs")

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
                self._client = client
                self._initialized = True
                logger.info("Chroma vector components initialized.")

            except Exception as e:
                logger.error(f"Error initializing ChromaStore: {e}")
                client_to_stop = self._detach_state(client)
                if client_to_stop is not None:
                    client_to_stop = self._stop_client_legacy_path_under_lock(
                        client_to_stop
                    )
                init_error = e

        self._stop_client(client_to_stop)
        if init_error is not None:
            raise VectorStoreInitError() from init_error

    def get_query_engines(
        self, llm_provider, similarity_top_k=None, response_mode=None
    ):
        try:
            index_code = VectorStoreIndex.from_vector_store(
                self.vector_store_code,
                storage_context=self.storage_context_code,
                embed_model=self.embed_model_code,
            )
            index_docs = VectorStoreIndex.from_vector_store(
                self.vector_store_docs,
                storage_context=self.storage_context_docs,
                embed_model=self.embed_model_docs,
            )

            llm_code = self._build_llm(llm_provider)
            llm_docs = self._build_llm(llm_provider)

            top_k = similarity_top_k or self.query_config.get("similarity_top_k", 5)
            mode = response_mode or self.query_config.get("response_mode", "compact")

            qe_code = index_code.as_query_engine(
                llm=llm_code, similarity_top_k=top_k, response_mode=mode
            )
            qe_docs = index_docs.as_query_engine(
                llm=llm_docs, similarity_top_k=top_k, response_mode=mode
            )
            return (QueryEngineRetriever(qe_code), QueryEngineRetriever(qe_docs))
        except Exception as e:
            logger.error(f"Error creating Chroma query engines: {e}")
            raise QueryEngineInitError()

    def get_storage_contexts(self):
        return self.storage_context_code, self.storage_context_docs

    def close(self):
        with self._init_lock:
            client = self._detach_state()
            if client is not None:
                client = self._stop_client_legacy_path_under_lock(client)

        self._stop_client(client)
