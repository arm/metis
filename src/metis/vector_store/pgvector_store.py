# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.core import StorageContext, VectorStoreIndex
from sqlalchemy import create_engine, text
from metis.exceptions import (
    VectorStoreInitError,
    RetrieverInitError,
    VectorSchemaError,
)
from metis.vector_store.base import BaseVectorStore
from metis.vector_store.retrievers import LlamaIndexNodeRetriever, QueryAnswerRetriever
from metis.vector_store.retrievers import query_chat_model_kwargs
from llama_index.vector_stores.postgres import PGVectorStore
from sqlalchemy.engine.url import make_url


import logging

logger = logging.getLogger(__name__)


HALFVEC_HNSW_DIST_METHODS = {
    "vector_l2_ops": "halfvec_l2_ops",
    "vector_ip_ops": "halfvec_ip_ops",
    "vector_cosine_ops": "halfvec_cosine_ops",
}


def normalize_hnsw_kwargs(hnsw_kwargs, *, use_halfvec):
    if hnsw_kwargs is None:
        return None
    normalized = dict(hnsw_kwargs)
    if use_halfvec:
        dist_method = normalized.get("hnsw_dist_method")
        if dist_method in HALFVEC_HNSW_DIST_METHODS:
            normalized["hnsw_dist_method"] = HALFVEC_HNSW_DIST_METHODS[dist_method]
    return normalized


def copy_hnsw_kwargs(hnsw_kwargs):
    if hnsw_kwargs is None:
        return None
    return hnsw_kwargs.copy()


class PGVectorStoreImpl(BaseVectorStore):
    def __init__(
        self,
        connection_string,
        project_schema,
        embed_model_code,
        embed_model_docs,
        embed_dim,
        query_config=None,
        hnsw_kwargs=None,
        use_halfvec=False,
    ):
        self.connection_string = connection_string
        self.project_schema = project_schema
        self.embed_model_code = embed_model_code
        self.embed_model_docs = embed_model_docs
        self.embed_dim = embed_dim
        self.query_config = query_config or {}
        self.use_halfvec = bool(use_halfvec)
        self.hnsw_kwargs = normalize_hnsw_kwargs(
            hnsw_kwargs,
            use_halfvec=self.use_halfvec,
        )
        self._initialized = False

    def init(self):
        if self._initialized:
            return
        try:
            url = make_url(self.connection_string)
            db_name = url.database

            self.vector_store_code = PGVectorStore.from_params(
                database=db_name,
                host=url.host,
                password=url.password,
                port=url.port,
                user=url.username,
                table_name="code",
                schema_name=self.project_schema,
                embed_dim=self.embed_dim,
                hnsw_kwargs=copy_hnsw_kwargs(self.hnsw_kwargs),
                use_halfvec=self.use_halfvec,
            )
            self.vector_store_docs = PGVectorStore.from_params(
                database=db_name,
                host=url.host,
                password=url.password,
                port=url.port,
                user=url.username,
                table_name="docs",
                schema_name=self.project_schema,
                embed_dim=self.embed_dim,
                hnsw_kwargs=copy_hnsw_kwargs(self.hnsw_kwargs),
                use_halfvec=self.use_halfvec,
            )

            self.storage_context_code = StorageContext.from_defaults(
                vector_store=self.vector_store_code
            )
            self.storage_context_docs = StorageContext.from_defaults(
                vector_store=self.vector_store_docs
            )

            self._initialized = True
            logger.info("Postgres vector components initialized.")

        except Exception as e:
            logger.error(f"Error initializing PGVectorStore: {e}")
            raise VectorStoreInitError()

    def get_retrievers(
        self,
        llm_provider,
        similarity_top_k,
        callback_manager=None,
        callbacks=None,
    ):
        try:
            index_code = VectorStoreIndex.from_vector_store(
                self.vector_store_code,
                storage_context=self.storage_context_code,
                embed_model=self.embed_model_code,
                callback_manager=callback_manager,
            )
            index_docs = VectorStoreIndex.from_vector_store(
                self.vector_store_docs,
                storage_context=self.storage_context_docs,
                embed_model=self.embed_model_docs,
                callback_manager=callback_manager,
            )
            chat_model_kwargs = query_chat_model_kwargs(
                self.query_config,
                callbacks=callbacks,
            )
            retriever_code = QueryAnswerRetriever(
                LlamaIndexNodeRetriever(
                    index_code.as_retriever(similarity_top_k=similarity_top_k)
                ),
                llm_provider,
                chat_model_kwargs=chat_model_kwargs,
            )
            retriever_docs = QueryAnswerRetriever(
                LlamaIndexNodeRetriever(
                    index_docs.as_retriever(similarity_top_k=similarity_top_k)
                ),
                llm_provider,
                chat_model_kwargs=chat_model_kwargs,
            )
            return (retriever_code, retriever_docs)
        except Exception as e:
            logger.error(f"Error creating PG retrievers: {e}")
            raise RetrieverInitError()

    def index_nodes(
        self,
        nodes_code,
        nodes_docs,
        *,
        embed_model_code,
        embed_model_docs,
        **embed_model_kwargs,
    ):
        VectorStoreIndex(
            nodes_code,
            storage_context=self.storage_context_code,
            embed_model=embed_model_code,
            **embed_model_kwargs,
        )
        VectorStoreIndex(
            nodes_docs,
            storage_context=self.storage_context_docs,
            embed_model=embed_model_docs,
            **embed_model_kwargs,
        )

    def get_index_handles(
        self,
        *,
        embed_model_code,
        embed_model_docs,
        **embed_model_kwargs,
    ):
        index_code = VectorStoreIndex.from_vector_store(
            self.vector_store_code,
            storage_context=self.storage_context_code,
            embed_model=embed_model_code,
            **embed_model_kwargs,
        )
        index_docs = VectorStoreIndex.from_vector_store(
            self.vector_store_docs,
            storage_context=self.storage_context_docs,
            embed_model=embed_model_docs,
            **embed_model_kwargs,
        )
        return index_code, index_docs

    def get_storage_contexts(self):
        return self.storage_context_code, self.storage_context_docs

    def check_project_schema_exists(self):
        engine = None
        try:
            engine = create_engine(self.connection_string)
            with engine.connect() as conn:
                result = conn.execute(
                    text(
                        "SELECT schema_name FROM information_schema.schemata WHERE schema_name = :schema_name"
                    ),
                    {"schema_name": self.project_schema},
                )
                exists = result.fetchone() is not None
                if exists:
                    logger.info(
                        f"Project schema '{self.project_schema}' exists in the database."
                    )
                else:
                    logger.info(
                        f"Project schema '{self.project_schema}' does not exist in the database."
                    )
                return exists
        except Exception:
            logger.error(f"Error checking for project schema '{self.project_schema}'")
            raise VectorSchemaError()
        finally:
            if engine is not None:
                engine.dispose()

    def close(self):
        self._initialized = False
        for attr in ("vector_store_code", "vector_store_docs"):
            store = getattr(self, attr, None)
            if store is None:
                continue
            close_fn = getattr(store, "close", None)
            if callable(close_fn):
                try:
                    close_fn()
                except Exception as e:
                    logger.warning(f"Error closing PG vector store '{attr}': {e}")
            for engine_attr in ("_engine", "engine"):
                candidate_engine = getattr(store, engine_attr, None)
                dispose_fn = getattr(candidate_engine, "dispose", None)
                if callable(dispose_fn):
                    try:
                        dispose_fn()
                    except Exception as e:
                        logger.warning(
                            f"Error disposing engine for PG vector store '{attr}': {e}"
                        )
            if hasattr(self, attr):
                delattr(self, attr)
        for attr in ("storage_context_code", "storage_context_docs"):
            if hasattr(self, attr):
                delattr(self, attr)
