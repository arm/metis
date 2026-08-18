# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import shutil

import pytest
from metis.configuration import load_execution_config
from metis.engine import MetisEngine
from metis.engine.concurrency import JobScheduler
from metis.runtime_settings import ModelToolSettings
from metis.runtime_settings import CapabilityRuntimeSettings
from unittest.mock import Mock, MagicMock


@pytest.fixture
def node_jobs():
    scheduler = JobScheduler(2)
    try:
        yield scheduler.limit(2)
    finally:
        scheduler.close()


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

    backend.get_retrievers = Mock(
        return_value=(
            Mock(get_relevant_documents=Mock(return_value=[_Doc("Code result")])),
            Mock(get_relevant_documents=Mock(return_value=[_Doc("Docs result")])),
        )
    )
    backend.get_storage_contexts = Mock(
        return_value=(mock_storage_context, mock_storage_context)
    )
    backend.index_nodes = Mock()
    backend.get_index_handles = Mock(return_value=(Mock(), Mock()))
    backend.vector_store_code = mock_vector_store
    backend.vector_store_docs = mock_vector_store

    return backend


@pytest.fixture
def dummy_llm():
    llm = Mock()
    llm.get_chat_model.return_value = MagicMock()
    llm.count_tokens = lambda text: len(text)
    return llm


@pytest.fixture
def dummy_embedding_provider():
    provider = Mock()
    provider.get_embed_model_code.return_value = Mock()
    provider.get_embed_model_docs.return_value = Mock()
    return provider


@pytest.fixture
def capability_settings():
    return CapabilityRuntimeSettings(
        model_tools=ModelToolSettings(max_rounds=6, max_contract_chars=6000),
        configurations={
            "index": {
                "search": {
                    "max_top_k": 4,
                    "code_top_k": 1,
                    "docs_top_k": 4,
                    "docs_char_ratio": 1.0,
                    "default_max_chars": 5000,
                    "max_chars": 7000,
                }
            },
            "navigation": {"timeout_seconds": 8, "max_chars": 16000},
        },
    )


@pytest.fixture
def execution_with_index():
    execution_config = load_execution_config()
    execution_config["stages"]["initialize"]["nodes"]["index"] = {
        "capabilities": ["index"]
    }
    return execution_config


@pytest.fixture
def engine(
    dummy_backend,
    dummy_llm,
    dummy_embedding_provider,
    capability_settings,
    execution_with_index,
    tmp_path,
):
    codebase_path = tmp_path / "data"
    shutil.copytree(Path(__file__).parent / "data", codebase_path)
    engine = MetisEngine(
        codebase_path=str(codebase_path),
        vector_backend=dummy_backend,
        language_plugin="c",
        llm_provider=dummy_llm,
        embedding_provider=dummy_embedding_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        capability_settings=capability_settings,
        execution_config=execution_with_index,
    )
    try:
        yield engine
    finally:
        engine.close()


def pytest_addoption(parser):
    parser.addoption(
        "--postgres",
        action="store_true",
        default=False,
        help="Run tests marked with @pytest.mark.postgres",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "postgres: tests that require a local Postgres service",
    )


def pytest_runtest_setup(item):
    if "postgres" in item.keywords and not item.config.getoption("--postgres"):
        pytest.skip("Use --postgres to run this test")
