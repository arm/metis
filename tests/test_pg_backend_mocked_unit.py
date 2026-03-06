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
    from metis.vector_store import pgvector_store as pgvector_store_module
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    from_params_calls = []
    storage_context_calls = []
    created_stores = []

    class _FakeStore:
        def __init__(self, name):
            self.name = name

    class _FakePGVectorStore:
        @staticmethod
        def from_params(**kwargs):
            from_params_calls.append(kwargs)
            store = _FakeStore(kwargs["table_name"])
            created_stores.append(store)
            return store

    class _FakeStorageContext:
        @staticmethod
        def from_defaults(vector_store):
            storage_context_calls.append(vector_store)
            return f"context-{vector_store.name}"

    pg = PGVectorStoreImpl(
        connection_string="postgresql://metis_user:metis_password@localhost:5432/metis_db",
        project_schema="test_schema",
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        embed_dim=1536,
    )

    monkeypatch.setattr(pgvector_store_module, "PGVectorStore", _FakePGVectorStore)
    monkeypatch.setattr(pgvector_store_module, "StorageContext", _FakeStorageContext)
    monkeypatch.setattr(
        pgvector_store_module,
        "make_url",
        lambda _url: SimpleNamespace(
            database="metis_db",
            host="localhost",
            password="metis_password",
            port=5432,
            username="metis_user",
        ),
    )

    pg.init()
    assert pg._initialized is True
    assert len(from_params_calls) == 2
    assert from_params_calls[0]["table_name"] == "code"
    assert from_params_calls[1]["table_name"] == "docs"
    assert from_params_calls[0]["schema_name"] == "test_schema"
    assert from_params_calls[1]["schema_name"] == "test_schema"
    assert pg.vector_store_code is created_stores[0]
    assert pg.vector_store_docs is created_stores[1]
    assert storage_context_calls == [created_stores[0], created_stores[1]]
    assert pg.get_storage_contexts() == ("context-code", "context-docs")


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


def test_pg_vectorstore_close_allows_reinit_while_dispose_is_slow(monkeypatch):
    dispose_started = threading.Event()
    release_dispose = threading.Event()
    from_params_calls = 0
    created_stores = []

    class _FakeEngine:
        def __init__(self, store_id):
            self.store_id = store_id
            self.dispose_calls = 0

        def dispose(self):
            self.dispose_calls += 1
            if self.store_id == 1:
                dispose_started.set()
                release_dispose.wait(timeout=2)

    class _FakeStore:
        def __init__(self, store_id):
            self.store_id = store_id
            self.close_calls = 0
            self._engine = _FakeEngine(store_id)

        def close(self):
            self.close_calls += 1

    class _FakePGVectorStore:
        @staticmethod
        def from_params(**kwargs):
            del kwargs
            nonlocal from_params_calls
            from_params_calls += 1
            store = _FakeStore(from_params_calls)
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

    pg.init()
    assert from_params_calls == 2

    errors = []

    def _call_close():
        try:
            pg.close()
        except Exception as exc:
            errors.append(exc)

    close_thread = threading.Thread(target=_call_close)
    close_thread.start()
    assert dispose_started.wait(timeout=2)

    def _call_init():
        try:
            pg.init()
        except Exception as exc:
            errors.append(exc)
        finally:
            init_completed.set()

    init_thread = threading.Thread(target=_call_init)
    init_completed = threading.Event()
    init_thread.start()
    assert init_completed.wait(timeout=2)
    init_thread.join(timeout=2)

    assert not init_thread.is_alive()
    assert not errors
    assert from_params_calls == 4
    assert pg._initialized is True
    assert pg.vector_store_code is created_stores[2]
    assert pg.vector_store_docs is created_stores[3]

    release_dispose.set()
    close_thread.join(timeout=2)

    assert not close_thread.is_alive()
    assert not errors
    assert created_stores[0].close_calls == 1
    assert created_stores[1].close_calls == 1
    assert created_stores[0]._engine.dispose_calls == 1
    assert created_stores[1]._engine.dispose_calls == 1

    pg.close()
    pg.close()

    assert created_stores[2].close_calls == 1
    assert created_stores[3].close_calls == 1
    assert created_stores[2]._engine.dispose_calls == 1
    assert created_stores[3]._engine.dispose_calls == 1
    assert pg._initialized is False


def test_pg_vectorstore_close_tolerates_store_cleanup_errors():
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    def _raise_close():
        raise RuntimeError("close boom")

    def _raise_dispose():
        raise RuntimeError("dispose boom")

    code_store = SimpleNamespace(
        close=_raise_close, _engine=SimpleNamespace(dispose=Mock())
    )
    docs_store = SimpleNamespace(
        close=Mock(), _engine=SimpleNamespace(dispose=_raise_dispose)
    )

    pg = PGVectorStoreImpl(
        connection_string="postgresql://...",
        project_schema="test_schema",
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        embed_dim=1536,
    )
    pg._initialized = True
    pg.vector_store_code = code_store
    pg.vector_store_docs = docs_store
    pg.storage_context_code = object()
    pg.storage_context_docs = object()

    pg.close()

    assert pg._initialized is False
    assert not hasattr(pg, "vector_store_code")
    assert not hasattr(pg, "vector_store_docs")
    assert not hasattr(pg, "storage_context_code")
    assert not hasattr(pg, "storage_context_docs")


def test_pg_vectorstore_close_deduplicates_shared_engine_dispose():
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    shared_engine = Mock(dispose=Mock())
    code_store = SimpleNamespace(close=Mock(), _engine=shared_engine)
    docs_store = SimpleNamespace(close=Mock(), engine=shared_engine)

    pg = PGVectorStoreImpl(
        connection_string="postgresql://...",
        project_schema="test_schema",
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        embed_dim=1536,
    )
    pg._initialized = True
    pg.vector_store_code = code_store
    pg.vector_store_docs = docs_store
    pg.storage_context_code = object()
    pg.storage_context_docs = object()

    pg.close()

    assert code_store.close.call_count == 1
    assert docs_store.close.call_count == 1
    assert shared_engine.dispose.call_count == 1


def test_pg_vectorstore_close_disposes_engine_attribute_variants():
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    code_engine = Mock(dispose=Mock())
    docs_engine = Mock(dispose=Mock())
    code_store = SimpleNamespace(close=Mock(), _engine=code_engine, engine=code_engine)
    docs_store = SimpleNamespace(close=Mock(), engine=docs_engine)

    pg = PGVectorStoreImpl(
        connection_string="postgresql://...",
        project_schema="test_schema",
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        embed_dim=1536,
    )
    pg._initialized = True
    pg.vector_store_code = code_store
    pg.vector_store_docs = docs_store
    pg.storage_context_code = object()
    pg.storage_context_docs = object()

    pg.close()

    assert pg._initialized is False
    assert code_store.close.call_count == 1
    assert docs_store.close.call_count == 1
    assert code_engine.dispose.call_count == 1
    assert docs_engine.dispose.call_count == 1
    assert not hasattr(pg, "vector_store_code")
    assert not hasattr(pg, "vector_store_docs")
    assert not hasattr(pg, "storage_context_code")
    assert not hasattr(pg, "storage_context_docs")

    pg.close()
    assert code_engine.dispose.call_count == 1
    assert docs_engine.dispose.call_count == 1
