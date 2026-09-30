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


@pytest.fixture
def postgres_connection():
    dsn = os.environ.get(
        "METIS_TEST_POSTGRES_DSN",
        "postgresql://metis_user:metis_password@localhost:5432/metis_db",
    )
    engine = create_engine(dsn)
    try:
        try:
            with engine.connect():
                pass
        except OperationalError:
            pytest.skip("Postgres is not available.")
        yield dsn, engine
    finally:
        engine.dispose()


@pytest.mark.postgres
def test_pg_backend_real_init(postgres_connection):
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    dsn, cleanup_engine = postgres_connection
    schema = "metis_init_" + uuid4().hex
    backend = PGVectorStoreImpl(
        connection_string=dsn,
        project_schema=schema,
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        embed_dim=1536,
    )

    try:
        backend.init()
        ctx_code, ctx_docs = backend.get_storage_contexts()
        assert ctx_code is not None
        assert ctx_docs is not None
    finally:
        for attr in ("vector_store_code", "vector_store_docs"):
            store = getattr(backend, attr, None)
            if store is not None:
                asyncio.run(store.close())
        with cleanup_engine.begin() as connection:
            connection.execute(DropSchema(schema, if_exists=True, cascade=True))


@pytest.mark.postgres
def test_pg_backend_initializes_empty_indexes_before_parallel_queries(
    caplog, postgres_connection
):
    from llama_index.core.schema import TextNode
    from llama_index.core.vector_stores.types import VectorStoreQuery

    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    dsn, cleanup_engine = postgres_connection
    schema = "metis_init_" + uuid4().hex
    backend = PGVectorStoreImpl(
        dsn,
        schema,
        Mock(),
        Mock(),
        3,
        hnsw_kwargs={"hnsw_m": 16, "hnsw_ef_construction": 64, "hnsw_ef_search": 40},
    )
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


@pytest.mark.postgres
def test_pg_backend_reports_hnsw_setup_failure(postgres_connection):
    from metis.exceptions import VectorStoreInitError
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    dsn, cleanup_engine = postgres_connection
    schema = "metis_init_failure_" + uuid4().hex
    backend = PGVectorStoreImpl(
        dsn,
        schema,
        Mock(),
        Mock(),
        3,
        hnsw_kwargs={"hnsw_m": 0, "hnsw_ef_construction": 64},
    )
    try:
        with pytest.raises(VectorStoreInitError):
            backend.init()
        assert backend._initialized is False
    finally:
        # LlamaIndex close() skips disposal after incomplete initialization.
        for attr in ("vector_store_code", "vector_store_docs"):
            store = getattr(backend, attr, None)
            engine = getattr(store, "_engine", None)
            if engine is not None:
                engine.dispose()
            async_engine = getattr(store, "_async_engine", None)
            if async_engine is not None:
                asyncio.run(async_engine.dispose())
        with cleanup_engine.begin() as connection:
            connection.execute(DropSchema(schema, if_exists=True, cascade=True))


@pytest.mark.postgres
def test_pg_backend_index_state_round_trip_with_a_mixed_case_schema(
    postgres_connection,
):
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    dsn, cleanup_engine = postgres_connection
    schema = "Metis_State_" + uuid4().hex
    backend = PGVectorStoreImpl(dsn, schema, Mock(), Mock(), 3)
    state = {"commit": "0" * 40, "operation": "index", "updated_at": "now"}
    try:
        backend.init()
        backend.set_index_state(state)

        assert backend.get_index_state() == state
        reader = PGVectorStoreImpl(dsn, schema, Mock(), Mock(), 3)
        assert reader.get_index_state() == state
    finally:
        for attr in ("vector_store_code", "vector_store_docs"):
            store = getattr(backend, attr, None)
            if store is not None:
                asyncio.run(store.close())
        with cleanup_engine.begin() as connection:
            connection.execute(DropSchema(schema.lower(), if_exists=True, cascade=True))
