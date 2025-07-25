# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
from metis.engine import MetisEngine
from unittest.mock import Mock
from metis.vector_store.chroma_store import ChromaStore
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
    }

    backend = ChromaStore(
        persist_dir=str(chroma_dir),
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
        query_config=runtime,
    )

    engine = MetisEngine(
        codebase_path="tests/data",
        vector_backend=backend,
        language_plugin="c",
        llm_provider=Mock(),
        **runtime,
    )

    engine.index_codebase()
