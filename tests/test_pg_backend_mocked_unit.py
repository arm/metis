# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from unittest.mock import Mock

import pytest


@pytest.mark.postgres
def test_pg_vectorstore_mocked_init(monkeypatch):
    from metis.vector_store import pgvector_store
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    code_store = Mock()
    docs_store = Mock()
    from_params = Mock(side_effect=[code_store, docs_store])
    context_from_defaults = Mock(side_effect=["code_ctx", "docs_ctx"])
    monkeypatch.setattr(pgvector_store.PGVectorStore, "from_params", from_params)
    monkeypatch.setattr(
        pgvector_store.StorageContext, "from_defaults", context_from_defaults
    )

    pg = PGVectorStoreImpl(
        connection_string="postgresql://metis_user:metis_password@localhost:5432/metis_db",
        project_schema="test_schema",
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        embed_dim=1536,
    )

    pg.init()
    assert pg.get_storage_contexts() == ("code_ctx", "docs_ctx")
    assert pg.vector_store_code is code_store
    assert pg.vector_store_docs is docs_store
    assert pg._initialized is True
    assert from_params.call_count == 2
    assert context_from_defaults.call_count == 2
    assert from_params.call_args_list[0].kwargs["use_halfvec"] is False
    assert from_params.call_args_list[1].kwargs["use_halfvec"] is False


@pytest.mark.postgres
def test_pg_vectorstore_passes_halfvec_and_rewrites_hnsw_dist_method(monkeypatch):
    from metis.vector_store import pgvector_store
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    from_params = Mock(side_effect=[Mock(), Mock()])
    monkeypatch.setattr(pgvector_store.PGVectorStore, "from_params", from_params)
    monkeypatch.setattr(
        pgvector_store.StorageContext,
        "from_defaults",
        Mock(side_effect=["code_ctx", "docs_ctx"]),
    )

    pg = PGVectorStoreImpl(
        connection_string="postgresql://metis_user:metis_password@localhost:5432/metis_db",
        project_schema="test_schema",
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        embed_dim=3072,
        hnsw_kwargs={
            "hnsw_m": 16,
            "hnsw_ef_construction": 64,
            "hnsw_dist_method": "vector_cosine_ops",
        },
        use_halfvec=True,
    )

    pg.init()

    assert from_params.call_count == 2
    for call in from_params.call_args_list:
        assert call.kwargs["embed_dim"] == 3072
        assert call.kwargs["use_halfvec"] is True
        assert call.kwargs["hnsw_kwargs"]["hnsw_dist_method"] == "halfvec_cosine_ops"


@pytest.mark.postgres
def test_pg_vectorstore_preserves_none_hnsw_kwargs(monkeypatch):
    from metis.vector_store import pgvector_store
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    from_params = Mock(side_effect=[Mock(), Mock()])
    monkeypatch.setattr(pgvector_store.PGVectorStore, "from_params", from_params)
    monkeypatch.setattr(
        pgvector_store.StorageContext,
        "from_defaults",
        Mock(side_effect=["code_ctx", "docs_ctx"]),
    )

    pg = PGVectorStoreImpl(
        connection_string="postgresql://metis_user:metis_password@localhost:5432/metis_db",
        project_schema="test_schema",
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        embed_dim=3072,
        hnsw_kwargs=None,
        use_halfvec=True,
    )

    pg.init()

    assert from_params.call_args_list[0].kwargs["hnsw_kwargs"] is None
    assert from_params.call_args_list[1].kwargs["hnsw_kwargs"] is None


@pytest.mark.postgres
def test_build_pg_backend_passes_halfvec_runtime_flag(monkeypatch):
    from metis.cli import utils

    constructed = {}

    class FakePGVectorStoreImpl:
        def __init__(self, **kwargs):
            constructed.update(kwargs)

    monkeypatch.setattr(utils, "PG_SUPPORTED", True)
    monkeypatch.setattr(utils, "PGVectorStoreImpl", FakePGVectorStoreImpl)

    backend = utils.build_pg_backend(
        SimpleNamespace(project_schema="test_schema"),
        {
            "pg_username": "metis_user",
            "pg_password": "metis_password",
            "pg_host": "localhost",
            "pg_port": 5432,
            "pg_db_name": "metis_db",
            "embed_dim": 3072,
            "pgvector_use_halfvec": True,
            "hnsw_kwargs": {"hnsw_m": 16},
        },
        Mock(),
        Mock(),
    )

    assert isinstance(backend, FakePGVectorStoreImpl)
    assert constructed["use_halfvec"] is True
    assert constructed["embed_dim"] == 3072
