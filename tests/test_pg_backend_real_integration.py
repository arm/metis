# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy import func
from sqlalchemy import select
from sqlalchemy import table
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.schema import DropSchema


@pytest.mark.postgres
def test_pg_backend_real_init():
    try:
        engine = create_engine(
            "postgresql://metis_user:metis_password@localhost:5432/metis_db"
        )
        engine.connect()
    except OperationalError:
        pytest.skip("Postgres is not available.")

    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    backend = PGVectorStoreImpl(
        connection_string="postgresql://metis_user:metis_password@localhost:5432/metis_db",
        project_schema="test_schema",
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        embed_dim=1536,
    )

    backend.init()
    ctx_code, ctx_docs = backend.get_storage_contexts()
    assert ctx_code is not None
    assert ctx_docs is not None


@pytest.mark.postgres
def test_pg_backend_initializes_empty_indexes_before_parallel_queries(caplog):
    from llama_index.core.schema import TextNode
    from llama_index.core.vector_stores.types import VectorStoreQuery

    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    dsn = os.environ.get(
        "METIS_TEST_POSTGRES_DSN",
        "postgresql://metis_user:metis_password@localhost:5432/metis_db",
    )
    schema = "metis_init_" + uuid4().hex
    backend = PGVectorStoreImpl(
        dsn,
        schema,
        Mock(),
        Mock(),
        3,
        hnsw_kwargs={"hnsw_m": 16, "hnsw_ef_construction": 64, "hnsw_ef_search": 40},
    )
    cleanup_engine = create_engine(dsn)
    stores = []
    try:
        backend.init()
        stores = [backend.vector_store_code, backend.vector_store_docs]
        for store, table_name in zip(stores, ("data_code", "data_docs"), strict=True):
            with store.client.connect() as connection:
                assert (
                    connection.execute(
                        select(func.count()).select_from(
                            table(table_name, schema=schema)
                        )
                    ).scalar_one()
                    == 0
                )
            store.add(
                [
                    TextNode(
                        id_="fixture", text="fixture content", embedding=[0.1, 0.2, 0.3]
                    )
                ]
            )

        def query(index):
            return (
                stores[index % 2]
                .query(
                    VectorStoreQuery(
                        query_embedding=[0.1, 0.2, 0.3], similarity_top_k=1
                    )
                )
                .ids
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            assert list(pool.map(query, range(24))) == [["fixture"]] * 24
        with stores[0].client.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM pg_indexes "
                        "WHERE schemaname=:schema AND indexdef LIKE '%USING hnsw%'"
                    ),
                    {"schema": schema},
                ).scalar_one()
                == 2
            )
        assert "PG Setup: Error" not in caplog.text
    finally:
        for store in stores:
            asyncio.run(store.close())
        with cleanup_engine.begin() as connection:
            connection.execute(DropSchema(schema, if_exists=True, cascade=True))
        cleanup_engine.dispose()
