# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
import threading
import sys
from unittest.mock import Mock
from types import SimpleNamespace
from types import ModuleType
from metis.exceptions import VectorStoreInitError


@pytest.mark.postgres
def test_pg_vectorstore_mocked_init(monkeypatch):

    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    pg = PGVectorStoreImpl(
        connection_string="postgresql://...",
        project_schema="test_schema",
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        embed_dim=1536,
    )

    monkeypatch.setattr(pg, "check_project_schema_exists", lambda: True)
    pg.vector_store_code = Mock(add=Mock(return_value=["mock_id"]))
    pg.vector_store_docs = Mock(add=Mock(return_value=["mock_id"]))
    pg.get_storage_contexts = lambda: ("code_ctx", "doc_ctx")

    pg.init()
    ctx = pg.get_storage_contexts()
    assert ctx == ("code_ctx", "doc_ctx")


def test_pg_vectorstore_init_is_thread_safe_and_reinitializable(monkeypatch):
    init_started = threading.Event()
    release_init = threading.Event()
    from_params_calls = 0
    storage_context_inits = 0

    class _FakeStore:
        def __init__(self):
            self.close = Mock()
            self._engine = Mock(dispose=Mock())

    class _FakePGVectorStore:
        @staticmethod
        def from_params(**kwargs):
            nonlocal from_params_calls
            from_params_calls += 1
            if from_params_calls == 1:
                init_started.set()
                release_init.wait(timeout=2)
            return _FakeStore()

    fake_pgvector_module = ModuleType("llama_index.vector_stores.postgres")
    fake_pgvector_module.PGVectorStore = _FakePGVectorStore
    monkeypatch.setitem(
        sys.modules, "llama_index.vector_stores.postgres", fake_pgvector_module
    )
    monkeypatch.delitem(sys.modules, "metis.vector_store.pgvector_store", raising=False)

    from metis.vector_store import pgvector_store as pgvector_store_module
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    class _FakeStorageContext:
        @staticmethod
        def from_defaults(vector_store):
            del vector_store
            nonlocal storage_context_inits
            storage_context_inits += 1
            return object()

    monkeypatch.setattr(
        pgvector_store_module,
        "make_url",
        lambda _url: SimpleNamespace(
            database="metis_db",
            host="localhost",
            password="password",
            port=5432,
            username="metis_user",
        ),
    )
    monkeypatch.setattr(pgvector_store_module, "StorageContext", _FakeStorageContext)

    pg = PGVectorStoreImpl(
        connection_string="postgresql://metis_user:metis_password@localhost:5432/metis_db",
        project_schema="test_schema",
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        embed_dim=1536,
    )

    errors = []

    def _call_init():
        try:
            pg.init()
        except Exception as exc:
            errors.append(exc)

    first = threading.Thread(target=_call_init)
    second = threading.Thread(target=_call_init)
    first.start()
    assert init_started.wait(timeout=2)
    second.start()
    release_init.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert not errors
    assert from_params_calls == 2
    assert storage_context_inits == 2

    pg.init()
    assert from_params_calls == 2
    assert storage_context_inits == 2

    first_code_store = pg.vector_store_code
    first_docs_store = pg.vector_store_docs
    pg.close()
    assert pg._initialized is False
    assert first_code_store.close.call_count == 1
    assert first_docs_store.close.call_count == 1
    assert first_code_store._engine.dispose.call_count == 1
    assert first_docs_store._engine.dispose.call_count == 1
    assert not hasattr(pg, "vector_store_code")
    assert not hasattr(pg, "vector_store_docs")
    assert not hasattr(pg, "storage_context_code")
    assert not hasattr(pg, "storage_context_docs")

    pg.init()
    assert from_params_calls == 4
    assert storage_context_inits == 4


def test_pg_vectorstore_init_failure_is_retryable(monkeypatch):
    from_params_calls = 0
    storage_context_inits = 0
    created_stores = []

    class _FakeStore:
        def __init__(self):
            self.close = Mock()
            self._engine = Mock(dispose=Mock())

    class _FakePGVectorStore:
        @staticmethod
        def from_params(**kwargs):
            del kwargs
            nonlocal from_params_calls
            from_params_calls += 1
            if from_params_calls == 2:
                raise RuntimeError("boom")
            store = _FakeStore()
            created_stores.append(store)
            return store

    fake_pgvector_module = ModuleType("llama_index.vector_stores.postgres")
    fake_pgvector_module.PGVectorStore = _FakePGVectorStore
    monkeypatch.setitem(
        sys.modules, "llama_index.vector_stores.postgres", fake_pgvector_module
    )
    monkeypatch.delitem(sys.modules, "metis.vector_store.pgvector_store", raising=False)

    from metis.vector_store import pgvector_store as pgvector_store_module
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    class _FakeStorageContext:
        @staticmethod
        def from_defaults(vector_store):
            del vector_store
            nonlocal storage_context_inits
            storage_context_inits += 1
            return object()

    monkeypatch.setattr(
        pgvector_store_module,
        "make_url",
        lambda _url: SimpleNamespace(
            database="metis_db",
            host="localhost",
            password="password",
            port=5432,
            username="metis_user",
        ),
    )
    monkeypatch.setattr(pgvector_store_module, "StorageContext", _FakeStorageContext)

    pg = PGVectorStoreImpl(
        connection_string="postgresql://metis_user:metis_password@localhost:5432/metis_db",
        project_schema="test_schema",
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        embed_dim=1536,
    )

    with pytest.raises(VectorStoreInitError):
        pg.init()
    assert from_params_calls == 2
    assert storage_context_inits == 0
    assert pg._initialized is False
    assert not hasattr(pg, "vector_store_code")
    assert not hasattr(pg, "vector_store_docs")
    assert not hasattr(pg, "storage_context_code")
    assert not hasattr(pg, "storage_context_docs")
    assert created_stores[0].close.call_count == 1
    assert created_stores[0]._engine.dispose.call_count == 1

    pg.init()
    assert from_params_calls == 4
    assert pg._initialized is True
    assert hasattr(pg, "vector_store_code")
    assert hasattr(pg, "vector_store_docs")
