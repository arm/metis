# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
from unittest.mock import patch
from metis.engine import MetisEngine
from metis.cli.utils import build_chroma_backend
from metis.vector_store.chroma_store import ChromaStore
from metis.providers.openai import OpenAIProvider
from llama_index.core.settings import Settings
from llama_index.core.embeddings.mock_embed_model import MockEmbedding


@pytest.mark.chroma
def test_chroma_backend_indexing(tmp_path):

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
        "enabled_tools": {"index"},
    }

    embed = MockEmbedding(embed_dim=8)
    backend = ChromaStore(
        persist_dir=str(chroma_dir),
        embed_model_code=embed,
        embed_model_docs=embed,
        query_config=runtime,
    )

    class _Provider:
        def get_embed_model_code(self, *, callback_manager=None):
            return embed

        def get_embed_model_docs(self, *, callback_manager=None):
            return embed

    engine = MetisEngine(
        codebase_path="tests/data",
        vector_backend=backend,
        language_plugin="c",
        llm_provider=_Provider(),
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


def test_build_chroma_backend_receives_full_runtime_config(tmp_path):
    base_url = "https://example.test/openai/v1"
    runtime = {
        "openai_api_base": base_url,
        "similarity_top_k": 7,
        "response_mode": "tree_summarize",
    }
    embed = MockEmbedding(embed_dim=8)

    class _Args:
        chroma_dir = str(tmp_path / "chroma_test")

    backend = build_chroma_backend(_Args(), runtime, embed, embed)

    assert backend.query_config is runtime
    assert backend.query_config["openai_api_base"] == base_url


def test_chroma_llm_uses_openai_provider_base_url(tmp_path):
    base_url = "https://example.test/openai/v1"
    runtime = {
        "llm_api_key": "test-key",
        "openai_api_base": base_url,
        "openai_default_headers": {"X-Test-Header": "test"},
        "model": "gpt-test",
        "llama_query_model": "gpt-test",
        "llama_query_temperature": 0.0,
        "llama_query_max_tokens": 256,
        "max_token_length": 32768,
        "code_embedding_model": "text-embedding-3-large",
        "docs_embedding_model": "text-embedding-3-large",
    }
    embed = MockEmbedding(embed_dim=8)
    backend = ChromaStore(
        persist_dir=str(tmp_path / "chroma_test"),
        embed_model_code=embed,
        embed_model_docs=embed,
        query_config=runtime,
    )

    llm = backend._build_llm(OpenAIProvider(runtime))

    assert llm.api_base == base_url
    assert llm.default_headers == {"X-Test-Header": "test"}
    assert llm.context_window == 32768
