# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import os
from unittest.mock import Mock
from unittest.mock import patch

import pytest
from chromadb.errors import NotFoundError
from llama_index.core.embeddings.mock_embed_model import MockEmbedding
from llama_index.core.settings import Settings

from metis.cli.utils import build_chroma_backend
from metis.engine import MetisEngine
from metis.exceptions import VectorStoreInitError
from metis.vector_store.chroma_store import ChromaStore


@pytest.mark.chroma
def test_chroma_backend_indexing(tmp_path, capability_settings):

    Settings.embed_model = MockEmbedding(embed_dim=8)

    chroma_dir = tmp_path / "chroma_test"
    os.makedirs(chroma_dir, exist_ok=True)

    runtime = {
        "max_workers": 2,
        "max_token_length": 2048,
        "llama_query_model": "gpt-test",
        "similarity_top_k": 5,
        "capability_settings": capability_settings,
    }

    embed = MockEmbedding(embed_dim=8)
    backend = ChromaStore(
        persist_dir=str(chroma_dir),
        embed_model_code=embed,
        embed_model_docs=embed,
        query_config=runtime,
    )

    engine = MetisEngine(
        codebase_path="tests/data",
        vector_backend=backend,
        language_plugin="c",
        llm_provider=object(),
        **runtime,
    )

    engine.indexing.index_codebase()


def test_chroma_store_forces_rust_bindings(tmp_path):
    embed = MockEmbedding(embed_dim=8)
    backend = ChromaStore(
        persist_dir=str(tmp_path / "chroma_test"),
        embed_model_code=embed,
        embed_model_docs=embed,
        query_config={},
    )

    with patch("metis.vector_store.chroma_store.PersistentClient") as client_ctor:
        client = client_ctor.return_value
        client.get_or_create_collection.side_effect = [object(), object()]

        with (
            patch(
                "metis.vector_store.chroma_store.ChromaVectorStore"
            ) as chroma_vector_store,
            patch("metis.vector_store.chroma_store.StorageContext") as storage_context,
        ):
            chroma_vector_store.side_effect = [object(), object()]
            storage_context.from_defaults.side_effect = [object(), object()]
            backend.init()

    settings = client_ctor.call_args.kwargs["settings"]
    assert settings.chroma_api_impl == "chromadb.api.rust.RustBindingsAPI"


def test_chroma_store_reset_recreates_collections(tmp_path):
    embed = MockEmbedding(embed_dim=8)
    backend = ChromaStore(
        persist_dir=str(tmp_path / "chroma_test"),
        embed_model_code=embed,
        embed_model_docs=embed,
        query_config={},
    )

    with patch("metis.vector_store.chroma_store.PersistentClient") as client_ctor:
        client = client_ctor.return_value
        client.delete_collection.side_effect = [None, NotFoundError("missing")]
        collections = [object(), object(), object(), object()]
        client.get_or_create_collection.side_effect = collections

        with (
            patch("metis.vector_store.chroma_store.ChromaVectorStore") as vector_store,
            patch("metis.vector_store.chroma_store.StorageContext") as storage_context,
        ):
            vector_store.side_effect = [object(), object(), object(), object()]
            storage_context.from_defaults.side_effect = [
                object(),
                object(),
                object(),
                object(),
            ]
            backend.init()
            backend.reset_index()

    assert client.delete_collection.call_count == 2
    client.delete_collection.assert_any_call("code")
    client.delete_collection.assert_any_call("docs")
    assert client.get_or_create_collection.call_count == 4
    client.delete_collection.side_effect = RuntimeError("storage failure")
    with pytest.raises(RuntimeError, match="storage failure"):
        backend.reset_index()
    assert client.get_or_create_collection.call_count == 4


def test_build_chroma_backend_receives_retriever_query_config(tmp_path):
    runtime = {
        "llm_provider_name": "openai",
        "llm_provider": {"api_key": "secret", "model": "gpt-test"},
        "llama_query_model": "gpt-test",
        "chat_model_kwargs": {"reasoning_effort": "low"},
        "similarity_top_k": 7,
    }
    embed = MockEmbedding(embed_dim=8)

    class _Args:
        chroma_dir = str(tmp_path / "chroma_test")

    docs_embed = MockEmbedding(embed_dim=16)
    backend = build_chroma_backend(_Args(), runtime, embed, docs_embed)

    assert backend.query_config == {
        "llama_query_model": "gpt-test",
        "chat_model_kwargs": {"reasoning_effort": "low"},
        "similarity_top_k": 7,
    }
    backend.collection_code, backend.collection_docs = object(), object()
    assert [
        (item._retriever._collection, item._retriever._embed_model, item._retriever._k)
        for item in backend.get_retrievers(Mock())
    ] == [
        (backend.collection_code, embed, 7),
        (backend.collection_docs, docs_embed, 7),
    ]


def test_chroma_failed_init_closes_client_without_masking_error(tmp_path):
    backend = ChromaStore(str(tmp_path), Mock(), Mock(), {})
    failure = RuntimeError("component failure")
    with (
        patch("metis.vector_store.chroma_store.PersistentClient") as client_constructor,
        patch.object(backend, "_set_collections", side_effect=failure),
    ):
        client = client_constructor.return_value
        client.close.side_effect = RuntimeError("close failure")
        with pytest.raises(VectorStoreInitError) as raised:
            backend.init()

    assert raised.value.__cause__ is failure
    client.close.assert_called_once_with()
    assert backend._client is None
    assert not backend._initialized
