# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
from metis.engine import MetisEngine
from unittest.mock import Mock, MagicMock


@pytest.fixture
def dummy_backend():
    backend = Mock()

    mock_vector_store = Mock()
    mock_vector_store.add = Mock(return_value=["mock_id"])
    mock_vector_store.stores_text = False

    mock_docstore = Mock()
    mock_docstore.add_documents = Mock()

    mock_index_struct = Mock()
    mock_index_struct.add_node = Mock()

    mock_storage_context = Mock()
    mock_storage_context.vector_store = mock_vector_store
    mock_storage_context.docstore = mock_docstore
    mock_storage_context.index_struct = mock_index_struct

    backend.init = Mock()

    class _Doc:
        def __init__(self, text):
            self.page_content = text

    backend.get_query_engines = Mock(
        return_value=(
            Mock(get_relevant_documents=Mock(return_value=[_Doc("Code result")])),
            Mock(get_relevant_documents=Mock(return_value=[_Doc("Docs result")])),
        )
    )
    backend.get_storage_contexts = Mock(
        return_value=(mock_storage_context, mock_storage_context)
    )
    backend.vector_store_code = mock_vector_store
    backend.vector_store_docs = mock_vector_store

    return backend


@pytest.fixture
def dummy_llm():
    llm = Mock()
    llm.get_query_engine_class.return_value = MagicMock
    llm.get_query_model_kwargs.return_value = {}
    llm.get_embed_model_code.return_value = Mock()
    llm.get_embed_model_docs.return_value = Mock()
    return llm


@pytest.fixture
def engine(dummy_backend, dummy_llm):
    return MetisEngine(
        codebase_path="./tests/data",
        vector_backend=dummy_backend,
        language_plugin="c",
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )


def pytest_addoption(parser):
    parser.addoption(
        "--postgres",
        action="store_true",
        default=False,
        help="Run tests marked with @pytest.mark.postgres",
    )


def pytest_runtest_setup(item):
    if "postgres" in item.keywords and not item.config.getoption("--postgres"):
        pytest.skip("Use --postgres to run this test")
