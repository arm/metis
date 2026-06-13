# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import pytest
import tempfile
import threading
from unittest.mock import Mock
from metis.engine import MetisEngine
from metis.exceptions import (
    PluginNotFoundError,
    RetrieverInitError,
    ToolDisabledError,
)
from metis.usage import UsageRuntime


def _embedding_provider(code_embedding_model=None, docs_embedding_model=None):
    provider = Mock()
    provider.get_embed_model_code.return_value = code_embedding_model or Mock()
    provider.get_embed_model_docs.return_value = docs_embedding_model or Mock()
    return provider


def test_supported_languages():
    langs = MetisEngine.supported_languages()
    assert "c" in langs
    assert "python" in langs
    assert "rust" in langs
    assert "typescript" in langs


def test_get_existing_plugin(engine):
    plugin = engine.get_plugin_from_name("c")
    assert plugin.get_name().lower() == "c"


def test_get_missing_plugin_raises(engine):
    with pytest.raises(PluginNotFoundError):
        engine.get_plugin_from_name("nonexistent")


def test_init_and_get_retrievers_raises_on_missing_backend():
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_retrievers = Mock(return_value=(None, None))
    engine = MetisEngine(
        vector_backend=bad_backend,
        llm_provider=Mock(),
        embedding_provider=_embedding_provider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools={"index"},
    )
    with pytest.raises(RetrieverInitError):
        engine._init_and_get_retrievers()


def test_init_and_get_default_unavailable_metisignore(caplog):
    caplog.set_level(logging.INFO, logger="metis")
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_retrievers = Mock(return_value=(None, None))
    engine = MetisEngine(
        vector_backend=bad_backend,
        llm_provider=Mock(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        metisignore_file=".metisignore_file",
    )
    assert engine.metisignore_file == ".metisignore_file"
    assert engine.repository.load_metisignore() is None
    assert engine.repository.load_metisignore() is None
    assert not any(
        "MetisIgnore file not loaded" in record.getMessage()
        for record in caplog.records
    )


def test_init_and_get_default_available_metisignore():
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_retrievers = Mock(return_value=(None, None))
    engine = None
    with tempfile.NamedTemporaryFile(
        mode="w+t", encoding="utf-8", suffix=".yaml"
    ) as temp_file:
        engine = MetisEngine(
            vector_backend=bad_backend,
            llm_provider=Mock(),
            max_workers=2,
            max_token_length=2048,
            llama_query_model="gpt-test",
            similarity_top_k=3,
            metisignore_file=temp_file.name,
        )
        assert engine.repository.load_metisignore() is not None
        assert engine.metisignore_file == temp_file.name
    assert engine is not None


def test_init_and_get_retrievers_is_thread_safe():
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=("code-retriever", "docs-retriever"))
    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        embedding_provider=_embedding_provider(),
        max_workers=4,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools={"index"},
    )

    results = []

    def _worker():
        results.append(engine._init_and_get_retrievers())

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results == [("code-retriever", "docs-retriever")] * 8
    backend.init.assert_called_once()
    backend.get_retrievers.assert_called_once()


def test_index_context_builds_embed_models_lazily_with_usage_callback_manager():
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=("code-retriever", "docs-retriever"))
    llm_provider = Mock()
    embedding_provider = Mock()
    code_embed_model = Mock()
    docs_embed_model = Mock()
    embedding_provider.get_embed_model_code.return_value = code_embed_model
    embedding_provider.get_embed_model_docs.return_value = docs_embed_model

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        embedding_provider=embedding_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools={"index"},
    )

    embedding_provider.get_embed_model_code.assert_not_called()
    embedding_provider.get_embed_model_docs.assert_not_called()

    assert engine.index_context.get_embedding_models() == (
        code_embed_model,
        docs_embed_model,
    )
    assert embedding_provider.get_embed_model_code.call_args.kwargs == {
        "callback_manager": engine.usage_runtime.hooks.callback_manager
    }
    assert embedding_provider.get_embed_model_docs.call_args.kwargs == {
        "callback_manager": engine.usage_runtime.hooks.callback_manager
    }
    assert backend.embed_model_code is code_embed_model
    assert backend.embed_model_docs is docs_embed_model


def test_index_tool_exposes_langchain_search_tool(engine):
    engine.vector_backend.get_retrievers.reset_mock()

    tools = engine.tools.langchain_tools()

    assert [tool.name for tool in tools] == ["index_search"]
    assert "keyword-only" in tools[0].args_schema["properties"]["query"]["description"]
    assert tools[0].args_schema["properties"]["source"]["enum"] == [
        "both",
        "docs",
        "code",
    ]
    assert tools[0].metadata["metis_contract_max_chars"] == 6000
    result = tools[0].invoke({"query": "allocator ownership"})
    assert "Code result" not in result
    assert "Docs result" in result
    assert [
        call.args[1] for call in engine.vector_backend.get_retrievers.call_args_list
    ] == [
        4,
    ]


def test_index_search_uses_manifest_tool_config(monkeypatch):
    class _Doc:
        def __init__(self, text):
            self.page_content = text

    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(
        return_value=(
            Mock(get_relevant_documents=Mock(return_value=[_Doc("C" * 100)])),
            Mock(get_relevant_documents=Mock(return_value=[_Doc("D" * 100)])),
        )
    )
    monkeypatch.setattr(
        "metis.engine.tools.catalog.get_tool_config",
        lambda _name: {
            "search": {
                "max_top_k": 3,
                "code_top_k": 1,
                "docs_top_k": 2,
                "docs_char_ratio": 0.75,
                "default_max_chars": 40,
                "max_chars": 40,
            }
        },
    )

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        embedding_provider=_embedding_provider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools={"index"},
    )

    result = engine.tools.index.search("allocator ownership", top_k=99, max_chars=99)

    assert [call.args[1] for call in backend.get_retrievers.call_args_list] == [1, 2]
    assert result.count("[truncated]") == 2


def test_index_search_can_retrieve_docs_only(monkeypatch):
    class _Doc:
        def __init__(self, text):
            self.page_content = text

    code_retriever = Mock(get_relevant_documents=Mock(return_value=[_Doc("code")]))
    docs_retriever = Mock(get_relevant_documents=Mock(return_value=[_Doc("docs")]))
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=(code_retriever, docs_retriever))
    monkeypatch.setattr(
        "metis.engine.tools.catalog.get_tool_config",
        lambda _name: {
            "search": {
                "max_top_k": 1,
                "code_top_k": 1,
                "docs_top_k": 1,
                "docs_char_ratio": 0.7,
                "default_max_chars": 5000,
                "max_chars": 7000,
            }
        },
    )

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        embedding_provider=_embedding_provider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools={"index"},
    )

    result = engine.tools.index.search("trust boundary", source="docs")

    assert "[CODE_CONTEXT]" not in result
    assert "[DOC_CONTEXT]" in result
    assert backend.get_retrievers.call_args.args[1] == 1
    code_retriever.get_relevant_documents.assert_not_called()
    docs_retriever.get_relevant_documents.assert_called_once_with("trust boundary")


def test_create_retrievers_passes_usage_callback_manager():
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=("code-retriever", "docs-retriever"))

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        embedding_provider=_embedding_provider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools={"index"},
    )

    engine._create_retrievers(5)

    assert (
        backend.get_retrievers.call_args.kwargs["callback_manager"]
        is engine.usage_runtime.hooks.callback_manager
    )
    assert (
        backend.get_retrievers.call_args.kwargs["callbacks"]
        == engine.usage_runtime.hooks.callbacks
    )


def test_review_graph_uses_usage_callbacks(monkeypatch):
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=("code-retriever", "docs-retriever"))
    llm_provider = Mock()
    llm_provider.get_chat_model.return_value = Mock(with_structured_output=Mock())

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools={"index"},
    )

    captured = {}

    def _fake_runner(_runner, request):
        captured["chat_model_kwargs"] = request.chat_model_kwargs
        captured["model_tools"] = request.model_tools
        captured["max_tool_rounds"] = request.max_tool_rounds
        return []

    monkeypatch.setattr(
        "metis.engine.llm_runner.JsonPromptRunner.invoke",
        _fake_runner,
    )
    graph = engine._get_review_graph()
    graph._invoke_review_model("system", "body")

    assert (
        captured["chat_model_kwargs"]["callbacks"]
        == engine.usage_runtime.hooks.callbacks
    )
    assert [tool.name for tool in captured["model_tools"]] == ["index_search"]
    assert captured["max_tool_rounds"] == 6


def test_review_graph_omits_model_tools_when_index_disabled(monkeypatch):
    llm_provider = Mock()
    llm_provider.get_chat_model.return_value = Mock(with_structured_output=Mock())

    engine = MetisEngine(
        vector_backend=Mock(),
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools=set(),
    )

    captured = {}

    def _fake_runner(_runner, request):
        captured["model_tools"] = request.model_tools
        captured["max_tool_rounds"] = request.max_tool_rounds
        return []

    monkeypatch.setattr(
        "metis.engine.llm_runner.JsonPromptRunner.invoke",
        _fake_runner,
    )
    graph = engine._get_review_graph()
    graph._invoke_review_model("system", "body")

    assert captured["model_tools"] == ()
    assert captured["max_tool_rounds"] is None


def test_engine_reuses_injected_runtime_and_backend_embed_models(tmp_path):
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=("code-retriever", "docs-retriever"))
    backend.embed_model_code = object()
    backend.embed_model_docs = object()
    llm_provider = Mock()
    runtime = UsageRuntime(tmp_path)

    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=backend,
        llm_provider=llm_provider,
        embedding_provider=_embedding_provider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        usage_runtime=runtime,
        enabled_tools={"index"},
    )

    assert engine.usage_runtime is runtime
    assert engine.index_context.get_embedding_models() == (
        backend.embed_model_code,
        backend.embed_model_docs,
    )
    llm_provider.get_chat_model.assert_not_called()


def test_engine_exposes_focused_services_without_compat_aliases():
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=("code-retriever", "docs-retriever"))
    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        embedding_provider=_embedding_provider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools={"index"},
    )

    engine.review.review_code = Mock(return_value=iter([{"file": "a.py"}]))
    engine.indexing.update_index = Mock()

    results = list(engine.review.review_code())

    assert engine.repository is not None
    assert engine.index_context is not None
    assert engine.tools.index is engine.index_context
    assert engine.review is not None
    assert engine.indexing is not None
    assert engine.indexing is engine.index_context.indexing
    assert not hasattr(engine, "embedding_provider")
    assert not hasattr(engine, "review_service")
    assert not hasattr(engine, "indexing_service")
    assert results == [{"file": "a.py"}]
    engine.indexing.update_index("diff --git")
    engine.indexing.update_index.assert_called_once_with("diff --git")


def test_index_prepare_nodes_resets_backend_index_when_supported(monkeypatch):
    backend = Mock()
    backend.init = Mock()
    backend.reset_index = Mock()
    backend.get_retrievers = Mock(return_value=("code-retriever", "docs-retriever"))

    embedding_provider = _embedding_provider()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        embedding_provider=embedding_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools={"index"},
    )

    class _Reader:
        def __init__(self, **_kwargs):
            pass

        def load_data(self):
            return []

    monkeypatch.setattr("metis.engine.indexing_service.SimpleDirectoryReader", _Reader)
    engine.indexing.index_prepare_nodes()

    embedding_provider.get_embed_model_code.assert_called_once()
    embedding_provider.get_embed_model_docs.assert_called_once()
    backend.init.assert_called_once()
    backend.reset_index.assert_called_once()


def test_index_finalize_embeddings_delegates_node_writes_to_backend():
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=("code-retriever", "docs-retriever"))
    backend.index_nodes = Mock()
    code_embed_model = Mock()
    docs_embed_model = Mock()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        embedding_provider=_embedding_provider(code_embed_model, docs_embed_model),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools={"index"},
    )
    engine._state.pending_nodes = (["code-node"], ["docs-node"])

    engine.indexing.index_finalize_embeddings()

    backend.index_nodes.assert_called_once_with(
        ["code-node"],
        ["docs-node"],
        embed_model_code=code_embed_model,
        embed_model_docs=docs_embed_model,
        callback_manager=engine.usage_runtime.hooks.callback_manager,
    )
    assert engine._state.pending_nodes is None


def test_close_clears_retriever_cache_and_closes_backend():
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=("code-retriever", "docs-retriever"))
    backend.close = Mock()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        embedding_provider=_embedding_provider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools={"index"},
    )

    assert engine._init_and_get_retrievers() == ("code-retriever", "docs-retriever")
    assert backend.get_retrievers.call_count == 1

    engine.close()

    assert engine._state.retriever_code is None
    assert engine._state.retriever_docs is None
    backend.close.assert_called_once()

    assert engine._init_and_get_retrievers() == ("code-retriever", "docs-retriever")
    assert backend.get_retrievers.call_count == 2


def test_disabled_index_tool_blocks_required_index_access():
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=("code-retriever", "docs-retriever"))
    backend.close = Mock()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        enabled_tools=set(),
    )

    assert engine.tools.index.enabled is False
    with pytest.raises(ToolDisabledError):
        engine._init_and_get_retrievers()
    with pytest.raises(ToolDisabledError):
        engine.indexing.count_index_items()

    engine.close()

    backend.init.assert_not_called()
    backend.get_retrievers.assert_not_called()
    backend.close.assert_not_called()
