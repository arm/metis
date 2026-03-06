# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
import threading
from unittest.mock import Mock
from metis.engine import MetisEngine
from metis.exceptions import VectorStoreInitError
from metis.vector_store.chroma_store import ChromaStore
from llama_index.core.settings import Settings
from llama_index.core.embeddings.mock_embed_model import MockEmbedding


@pytest.mark.chroma
def test_chroma_backend_indexing(tmp_path, monkeypatch):
    monkeypatch.setattr(
        Settings, "_embed_model", MockEmbedding(embed_dim=8), raising=False
    )

    chroma_dir = tmp_path / "chroma_test"
    os.makedirs(chroma_dir, exist_ok=True)

    runtime = {
        "llm_api_key": "test-key",
        "max_workers": 2,
        "max_token_length": 2048,
        "llama_query_model": "gpt-test",
        "similarity_top_k": 5,
        "response_mode": "compact",
        "code_embedding_model": "test-code-embed",
        "docs_embedding_model": "test-docs-embed",
    }

    embed = MockEmbedding(embed_dim=8)
    backend = ChromaStore(
        persist_dir=str(chroma_dir),
        embed_model_code=embed,
        embed_model_docs=embed,
        query_config=runtime,
    )

    class _Provider:
        def get_embed_model_code(self):
            return embed

        def get_embed_model_docs(self):
            return embed

    engine = MetisEngine(
        codebase_path="tests/data",
        vector_backend=backend,
        language_plugin="c",
        llm_provider=_Provider(),
        **runtime,
    )

    engine.index_codebase()
    assert backend._initialized is True
    code_ctx, docs_ctx = backend.get_storage_contexts()
    assert code_ctx is not None
    assert docs_ctx is not None
    engine.close()


@pytest.mark.chroma
def test_chroma_store_init_is_thread_safe_and_reinitializable(monkeypatch, tmp_path):
    from metis.vector_store import chroma_store as chroma_store_module

    init_started = threading.Event()
    release_init = threading.Event()
    client_init_calls = 0
    vector_store_inits = 0
    storage_context_inits = 0

    class _FakeClient:
        def __init__(self, path, settings):
            del path, settings
            nonlocal client_init_calls
            client_init_calls += 1
            self.close = Mock()
            self._system = Mock(stop=Mock())
            if client_init_calls == 1:
                init_started.set()
                release_init.wait(timeout=2)

        def get_or_create_collection(self, name):
            return {"name": name}

    class _FakeChromaVectorStore:
        def __init__(self, chroma_collection, embed_model):
            nonlocal vector_store_inits
            vector_store_inits += 1
            self.collection = chroma_collection
            self.embed_model = embed_model

    class _FakeStorageContext:
        @staticmethod
        def from_defaults(vector_store):
            del vector_store
            nonlocal storage_context_inits
            storage_context_inits += 1
            return object()

    monkeypatch.setattr(chroma_store_module, "PersistentClient", _FakeClient)
    monkeypatch.setattr(
        chroma_store_module, "ChromaVectorStore", _FakeChromaVectorStore
    )
    monkeypatch.setattr(chroma_store_module, "StorageContext", _FakeStorageContext)

    store = ChromaStore(
        persist_dir=str(tmp_path / "chroma_test"),
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        query_config={},
    )

    errors = []

    def _call_init():
        try:
            store.init()
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
    assert client_init_calls == 1
    assert vector_store_inits == 2
    assert storage_context_inits == 2

    store.init()
    assert client_init_calls == 1
    assert vector_store_inits == 2
    assert storage_context_inits == 2

    first_client = store._client
    store.close()
    assert first_client.close.call_count == 1
    assert store._initialized is False
    assert not hasattr(store, "vector_store_code")
    assert not hasattr(store, "vector_store_docs")
    assert not hasattr(store, "storage_context_code")
    assert not hasattr(store, "storage_context_docs")

    store.init()
    assert client_init_calls == 2
    assert vector_store_inits == 4
    assert storage_context_inits == 4


@pytest.mark.chroma
def test_chroma_store_init_failure_is_retryable(monkeypatch, tmp_path):
    from metis.vector_store import chroma_store as chroma_store_module

    client_init_calls = 0
    client_instances = []
    vector_store_inits = 0
    storage_context_inits = 0

    class _FakeClient:
        def __init__(self, path, settings):
            del path, settings
            nonlocal client_init_calls
            client_init_calls += 1
            self.close = Mock()
            self._system = Mock(stop=Mock())
            client_instances.append(self)

        def get_or_create_collection(self, name):
            if client_init_calls == 1 and name == "docs":
                raise RuntimeError("boom")
            return {"name": name}

    class _FakeChromaVectorStore:
        def __init__(self, chroma_collection, embed_model):
            del chroma_collection, embed_model
            nonlocal vector_store_inits
            vector_store_inits += 1

    class _FakeStorageContext:
        @staticmethod
        def from_defaults(vector_store):
            del vector_store
            nonlocal storage_context_inits
            storage_context_inits += 1
            return object()

    monkeypatch.setattr(chroma_store_module, "PersistentClient", _FakeClient)
    monkeypatch.setattr(
        chroma_store_module, "ChromaVectorStore", _FakeChromaVectorStore
    )
    monkeypatch.setattr(chroma_store_module, "StorageContext", _FakeStorageContext)

    store = ChromaStore(
        persist_dir=str(tmp_path / "chroma_test"),
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        query_config={},
    )

    with pytest.raises(VectorStoreInitError):
        store.init()
    assert client_init_calls == 1
    assert len(client_instances) == 1
    assert client_instances[0].close.call_count == 1
    assert store._initialized is False
    assert store._client is None
    assert not hasattr(store, "vector_store_code")
    assert not hasattr(store, "vector_store_docs")
    assert not hasattr(store, "storage_context_code")
    assert not hasattr(store, "storage_context_docs")

    store.init()
    assert client_init_calls == 2
    assert vector_store_inits == 2
    assert storage_context_inits == 2
    assert store._initialized is True


@pytest.mark.chroma
def test_chroma_store_close_handles_client_close_error(tmp_path):
    close_mock = Mock(side_effect=RuntimeError("close failed"))
    client = Mock()
    client.close = close_mock
    store = ChromaStore(
        persist_dir=str(tmp_path / "chroma-test"),
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        query_config={},
    )
    store._client = client
    store._initialized = True
    store.vector_store_code = object()
    store.vector_store_docs = object()
    store.storage_context_code = object()
    store.storage_context_docs = object()

    store.close()

    assert close_mock.call_count == 1
    assert store._initialized is False
    assert store._client is None
    assert not hasattr(store, "vector_store_code")
    assert not hasattr(store, "vector_store_docs")
    assert not hasattr(store, "storage_context_code")
    assert not hasattr(store, "storage_context_docs")


@pytest.mark.chroma
def test_chroma_store_prefers_client_close_over_system_stop(tmp_path):
    close_mock = Mock()
    stop_mock = Mock()
    client = Mock()
    client.close = close_mock
    client._system = Mock(stop=stop_mock)
    store = ChromaStore(
        persist_dir=str(tmp_path / "chroma-test"),
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        query_config={},
    )

    store._stop_client(client)

    assert close_mock.call_count == 1
    assert stop_mock.call_count == 0


@pytest.mark.chroma
def test_chroma_store_falls_back_to_system_stop_when_close_unavailable(tmp_path):
    stop_mock = Mock()
    client = type("_ClientWithoutClose", (), {})()
    client._system = type("_System", (), {"stop": stop_mock})()
    store = ChromaStore(
        persist_dir=str(tmp_path / "chroma-test"),
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        query_config={},
    )

    store._stop_client(client)

    assert stop_mock.call_count == 1


@pytest.mark.chroma
def test_chroma_store_init_failure_cleanup_handles_client_close_error(
    monkeypatch, tmp_path
):
    from metis.vector_store import chroma_store as chroma_store_module

    client_instances = []

    class _FailingClient:
        def __init__(self, path, settings):
            del path, settings
            self.close = Mock(side_effect=RuntimeError("close failed"))
            client_instances.append(self)

        def get_or_create_collection(self, name):
            if name == "docs":
                raise RuntimeError("boom")
            return {"name": name}

    monkeypatch.setattr(chroma_store_module, "PersistentClient", _FailingClient)
    store = ChromaStore(
        persist_dir=str(tmp_path / "chroma_test"),
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        query_config={},
    )

    with pytest.raises(VectorStoreInitError):
        store.init()

    assert len(client_instances) == 1
    assert client_instances[0].close.call_count == 1
    assert store._initialized is False
    assert store._client is None
    assert not hasattr(store, "vector_store_code")
    assert not hasattr(store, "vector_store_docs")
    assert not hasattr(store, "storage_context_code")
    assert not hasattr(store, "storage_context_docs")


@pytest.mark.chroma
def test_chroma_store_close_allows_reinit_while_client_close_is_slow(
    monkeypatch, tmp_path
):
    from metis.vector_store import chroma_store as chroma_store_module

    close_started = threading.Event()
    release_close = threading.Event()
    client_init_calls = 0
    client_instances = []

    class _FakeClient:
        def __init__(self, path, settings):
            del path, settings
            nonlocal client_init_calls
            client_init_calls += 1
            self.client_id = client_init_calls
            self.close_calls = 0
            client_instances.append(self)

        def get_or_create_collection(self, name):
            return {"name": name}

        def close(self):
            self.close_calls += 1
            if self.client_id == 1:
                close_started.set()
                release_close.wait(timeout=2)

    class _FakeChromaVectorStore:
        def __init__(self, chroma_collection, embed_model):
            self.chroma_collection = chroma_collection
            self.embed_model = embed_model

    class _FakeStorageContext:
        @staticmethod
        def from_defaults(vector_store):
            del vector_store
            return object()

    monkeypatch.setattr(chroma_store_module, "PersistentClient", _FakeClient)
    monkeypatch.setattr(
        chroma_store_module, "ChromaVectorStore", _FakeChromaVectorStore
    )
    monkeypatch.setattr(chroma_store_module, "StorageContext", _FakeStorageContext)

    store = ChromaStore(
        persist_dir=str(tmp_path / "chroma_test"),
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        query_config={},
    )

    store.init()
    assert client_init_calls == 1

    errors = []

    def _call_close():
        try:
            store.close()
        except Exception as exc:
            errors.append(exc)

    close_thread = threading.Thread(target=_call_close)
    close_thread.start()
    assert close_started.wait(timeout=2)

    init_completed = threading.Event()

    def _call_init():
        try:
            store.init()
        except Exception as exc:
            errors.append(exc)
        finally:
            init_completed.set()

    init_thread = threading.Thread(target=_call_init)
    init_thread.start()
    assert init_completed.wait(timeout=2)
    init_thread.join(timeout=2)

    assert not init_thread.is_alive()
    assert not errors
    assert client_init_calls == 2
    assert store._initialized is True
    assert store._client is client_instances[1]
    assert client_instances[1].close_calls == 0

    release_close.set()
    close_thread.join(timeout=2)

    assert not close_thread.is_alive()
    assert not errors
    assert client_instances[0].close_calls == 1

    store.close()
    store.close()
    assert client_instances[1].close_calls == 1
    assert store._initialized is False


@pytest.mark.chroma
def test_chroma_store_close_blocks_reinit_while_legacy_system_stop_is_slow(
    monkeypatch, tmp_path
):
    from metis.vector_store import chroma_store as chroma_store_module

    stop_started = threading.Event()
    release_stop = threading.Event()
    init_completed = threading.Event()
    client_init_calls = 0
    client_instances = []

    class _System:
        def __init__(self, client):
            self._client = client

        def stop(self):
            self._client.stop_calls += 1
            if self._client.client_id == 1:
                stop_started.set()
                release_stop.wait(timeout=2)

    class _FakeClient:
        def __init__(self, path, settings):
            del path, settings
            nonlocal client_init_calls
            client_init_calls += 1
            self.client_id = client_init_calls
            self.stop_calls = 0
            self._system = _System(self)
            client_instances.append(self)

        def get_or_create_collection(self, name):
            return {"name": name}

    class _FakeChromaVectorStore:
        def __init__(self, chroma_collection, embed_model):
            self.chroma_collection = chroma_collection
            self.embed_model = embed_model

    class _FakeStorageContext:
        @staticmethod
        def from_defaults(vector_store):
            del vector_store
            return object()

    monkeypatch.setattr(chroma_store_module, "PersistentClient", _FakeClient)
    monkeypatch.setattr(
        chroma_store_module, "ChromaVectorStore", _FakeChromaVectorStore
    )
    monkeypatch.setattr(chroma_store_module, "StorageContext", _FakeStorageContext)

    store = ChromaStore(
        persist_dir=str(tmp_path / "chroma_test"),
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        query_config={},
    )

    store.init()
    assert client_init_calls == 1

    errors = []

    def _call_close():
        try:
            store.close()
        except Exception as exc:
            errors.append(exc)

    close_thread = threading.Thread(target=_call_close)
    close_thread.start()
    assert stop_started.wait(timeout=2)

    def _call_init():
        try:
            store.init()
        except Exception as exc:
            errors.append(exc)
        finally:
            init_completed.set()

    init_thread = threading.Thread(target=_call_init)
    init_thread.start()
    assert not init_completed.wait(timeout=0.2)

    release_stop.set()
    assert init_completed.wait(timeout=2)
    init_thread.join(timeout=2)
    close_thread.join(timeout=2)

    assert not init_thread.is_alive()
    assert not close_thread.is_alive()
    assert not errors
    assert client_init_calls == 2
    assert store._initialized is True
    assert store._client is client_instances[1]
    assert client_instances[0].stop_calls == 1
    assert client_instances[1].stop_calls == 0

    store.close()
    store.close()
    assert client_instances[1].stop_calls == 1
    assert store._initialized is False
