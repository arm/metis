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
def test_chroma_backend_indexing(tmp_path):
    original_embed_model = getattr(Settings, "_embed_model", None)
    Settings.embed_model = MockEmbedding(embed_dim=8)

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

    try:
        engine.index_codebase()
    finally:
        Settings._embed_model = original_embed_model


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
    assert first_client._system.stop.call_count == 1
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
    assert client_instances[0]._system.stop.call_count == 1
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
