# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.vector_stores.chroma import ChromaVectorStore
from llama_index.core import StorageContext, VectorStoreIndex
from chromadb import PersistentClient
from metis.exceptions import VectorStoreInitError, QueryEngineInitError
from metis.vector_store.base import BaseVectorStore, QueryEngineRetriever
from chromadb.config import Settings

import logging

logger = logging.getLogger(__name__)


class ChromaStore(BaseVectorStore):
    def __init__(self, persist_dir, embed_model_code, embed_model_docs, query_config):
        self.persist_dir = persist_dir
        self.embed_model_code = embed_model_code
        self.embed_model_docs = embed_model_docs
        self.query_config = query_config

    def init(self):
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
            logger.info("Chroma vector components initialized.")

        except Exception as e:
            logger.error(f"Error initializing ChromaStore: {e}")
            raise VectorStoreInitError()

    def get_query_engines(self, similarity_top_k=None, response_mode=None):
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

            top_k = similarity_top_k or self.query_config.get("similarity_top_k", 5)
            mode = response_mode or self.query_config.get("response_mode", "compact")

            qe_code = index_code.as_query_engine(
                similarity_top_k=top_k, response_mode=mode
            )
            qe_docs = index_docs.as_query_engine(
                similarity_top_k=top_k, response_mode=mode
            )
            return (QueryEngineRetriever(qe_code), QueryEngineRetriever(qe_docs))
        except Exception as e:
            logger.error(f"Error creating Chroma query engines: {e}")
            raise QueryEngineInitError()

    def get_storage_contexts(self):
        return self.storage_context_code, self.storage_context_docs
