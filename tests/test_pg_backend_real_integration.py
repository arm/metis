# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock
from uuid import uuid4

import pytest
from sqlalchemy import column
from sqlalchemy import create_engine
from sqlalchemy import func
from sqlalchemy import select
from sqlalchemy import table
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import DBAPIError
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
def test_pg_backend_normalizes_nul_text_and_nested_metadata(postgres_connection):
    from llama_index.core.embeddings import MockEmbedding
    from llama_index.core.schema import TextNode

    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    dsn, cleanup_engine = postgres_connection
    schema = "metis_nul_" + uuid4().hex
    embed = MockEmbedding(embed_dim=3)
    backend = PGVectorStoreImpl(dsn, schema, embed, embed, 3)
    nodes = [
        TextNode(
            id_="code-stable",
            text="before\x00after",
            metadata={"nested": {"key\x00": ["value\x00"]}},
        ),
        TextNode(id_="docs-stable", text="documentation\x00"),
    ]
    originals = [node.model_dump() for node in nodes]
    try:
        backend.init()
        # Establish the underlying PostgreSQL failure without provider calls.
        with pytest.raises((ValueError, DBAPIError), match="NUL|0x00|0000"):
            backend.vector_store_code.add(
                [TextNode(text="raw\x00", embedding=[0.1, 0.2, 0.3])]
            )
        backend.index_nodes(
            [nodes[0]], [nodes[1]], embed_model_code=embed, embed_model_docs=embed
        )
        with cleanup_engine.connect() as connection:
            for name, original in zip(("code", "docs"), nodes, strict=True):
                rows = table(
                    f"data_{name}",
                    column("node_id"),
                    column("text"),
                    column("metadata_"),
                    schema=schema,
                )
                row = connection.execute(select(rows)).mappings().one()
                assert row["node_id"] == original.node_id
                assert row["text"] == original.text.replace("\x00", "\\u0000")
                if name == "code":
                    assert row["metadata_"]["nested"] == {
                        r"key\u0000": [r"value\u0000"]
                    }
        assert [node.model_dump() for node in nodes] == originals
    finally:
        for attr in ("vector_store_code", "vector_store_docs"):
            store = getattr(backend, attr, None)
            if store is not None:
                asyncio.run(store.close())
        with cleanup_engine.begin() as connection:
            connection.execute(DropSchema(schema, if_exists=True, cascade=True))


@pytest.mark.postgres
@pytest.mark.parametrize("added", [False, True])
@pytest.mark.parametrize("kind,extension", [("code", "c"), ("docs", "md")])
def test_pg_incremental_index_normalizes_nul_before_persistence(
    postgres_connection, engine, added, kind, extension
):
    from llama_index.core.embeddings import MockEmbedding
    from llama_index.core.schema import NodeRelationship
    from llama_index.core.schema import RelatedNodeInfo
    from llama_index.core.schema import TextNode

    from metis.engine.capabilities.indexing import IndexingService
    from metis.engine.runtime import EngineState
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    dsn, cleanup_engine = postgres_connection
    schema = "metis_nul_update_" + uuid4().hex
    embed = MockEmbedding(embed_dim=3)
    backend = PGVectorStoreImpl(dsn, schema, embed, embed, 3)
    indexing = IndexingService(
        replace(engine._config, vector_backend=backend),
        EngineState(),
        engine.repository,
        get_embedding_models=lambda: (embed, embed),
    )
    path = Path(engine._config.codebase_path) / f"nul.{extension}"
    source = (
        "// before\x00after\nint value;\n" if kind == "code" else "before\x00after\n"
    )
    path.write_text(source, encoding="utf-8")
    doc_id = f"{path.parent.name}/{path.name}"
    patch = (
        f"--- /dev/null\n+++ b/{path.name}\n@@ -0,0 +1 @@\n+new\n"
        if added
        else f"--- a/{path.name}\n+++ b/{path.name}\n@@ -1 +1 @@\n-old\n+new\n"
    )
    try:
        backend.init()
        store = getattr(backend, f"vector_store_{kind}")
        if not added:
            store.add(
                [
                    TextNode(
                        id_="old-node",
                        text="old",
                        embedding=[0.1, 0.2, 0.3],
                        relationships={
                            NodeRelationship.SOURCE: RelatedNodeInfo(node_id=doc_id)
                        },
                    )
                ]
            )
        store.add(
            [TextNode(id_="untouched", text="untouched", embedding=[0.1, 0.2, 0.3])]
        )

        indexing.update_index(patch)

        with cleanup_engine.connect() as connection:
            data = table(
                f"data_{kind}",
                column("node_id"),
                column("text"),
                column("metadata_"),
                schema=schema,
            )
            rows = connection.execute(select(data)).mappings().all()
        assert any(row["node_id"] == "untouched" for row in rows)
        changed = [row for row in rows if row["node_id"] != "untouched"]
        assert changed
        assert all(row["node_id"] != "old-node" for row in changed)
        assert all(row["metadata_"]["ref_doc_id"] == doc_id for row in changed)
        assert any(r"before\u0000after" in row["text"] for row in changed)
        assert path.read_text(encoding="utf-8") == source
    finally:
        for attr in ("vector_store_code", "vector_store_docs"):
            store = getattr(backend, attr, None)
            if store is not None:
                asyncio.run(store.close())
        with cleanup_engine.begin() as connection:
            connection.execute(DropSchema(schema, if_exists=True, cascade=True))
