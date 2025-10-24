# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.core import StorageContext, VectorStoreIndex
from sqlalchemy import create_engine, text
from metis.exceptions import (
    VectorStoreInitError,
    QueryEngineInitError,
    VectorSchemaError,
)
from metis.vector_store.base import BaseVectorStore, QueryEngineRetriever
from llama_index.vector_stores.postgres import PGVectorStore
from sqlalchemy.engine.url import make_url


import logging

logger = logging.getLogger(__name__)


class PGVectorStoreImpl(BaseVectorStore):
    def __init__(
        self,
        connection_string,
        project_schema,
        embed_model_code,
        embed_model_docs,
        embed_dim,
        hnsw_kwargs=None,
    ):
        self.connection_string = connection_string
        self.project_schema = project_schema
        self.embed_model_code = embed_model_code
        self.embed_model_docs = embed_model_docs
        self.embed_dim = embed_dim
        self.hnsw_kwargs = hnsw_kwargs or {}

    def init(self):
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
                hnsw_kwargs=self.hnsw_kwargs.copy(),
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
                hnsw_kwargs=self.hnsw_kwargs.copy(),
            )

            self.storage_context_code = StorageContext.from_defaults(
                vector_store=self.vector_store_code
            )
            self.storage_context_docs = StorageContext.from_defaults(
                vector_store=self.vector_store_docs
            )

            logger.info("Postgres vector components initialized.")

        except Exception as e:
            logger.error(f"Error initializing PGVectorStore: {e}")
            raise VectorStoreInitError()

    def get_query_engines(self, similarity_top_k, response_mode):
        try:
            index_code = VectorStoreIndex.from_vector_store(
                self.vector_store_code, storage_context=self.storage_context_code
            )
            index_docs = VectorStoreIndex.from_vector_store(
                self.vector_store_docs, storage_context=self.storage_context_docs
            )

            qe_code = index_code.as_query_engine(
                similarity_top_k=similarity_top_k, response_mode=response_mode
            )
            qe_docs = index_docs.as_query_engine(
                similarity_top_k=similarity_top_k, response_mode=response_mode
            )
            return (QueryEngineRetriever(qe_code), QueryEngineRetriever(qe_docs))
        except Exception as e:
            logger.error(f"Error creating PG query engines: {e}")
            raise QueryEngineInitError()

    def get_storage_contexts(self):
        return self.storage_context_code, self.storage_context_docs

    def check_project_schema_exists(self):
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
