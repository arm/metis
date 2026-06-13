# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
from unittest.mock import Mock


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
