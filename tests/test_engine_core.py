# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import tempfile
import threading
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from metis.configuration import load_execution_config
from metis.engine import MetisEngine
from metis.engine.capabilities.engine import EngineCapabilities
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphReference
from metis.engine.execution.contracts import ExecutionStatus
from metis.engine.nodes.builtins import build_builtin_execution
from metis.engine.nodes.reachability.review import ReachabilityReviewService
from metis.engine.nodes.simple_llm_review.service import SimpleLlmReviewService
from metis.engine.stages.configuration import ExecutionConfiguration
from metis.engine.stages.review.models import ReviewCommand
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import ReviewStatus
from metis.engine.stages.review.models import StandardReviewResult
from metis.engine.tools.index import index_model_tools
from metis.exceptions import RetrieverInitError
from metis.runtime_settings import CapabilityRuntimeSettings
from metis.usage import UsageRuntime


def _embedding_provider(code_embedding_model=None, docs_embedding_model=None):
    provider = Mock()
    provider.get_embed_model_code.return_value = code_embedding_model or Mock()
    provider.get_embed_model_docs.return_value = docs_embedding_model or Mock()
    return provider


def _execution_with_index() -> dict[str, object]:
    execution = load_execution_config()
    execution["stages"]["initialize"]["nodes"]["index"] = {"capabilities": ["index"]}
    return execution


@pytest.mark.parametrize("max_workers", (0, -1, True, "2"))
def test_engine_rejects_invalid_max_workers(capability_settings, max_workers):
    with pytest.raises(
        ValueError,
        match="MetisEngine.max_workers must be a positive integer",
    ):
        MetisEngine(
            vector_backend=Mock(),
            llm_provider=Mock(),
            max_workers=max_workers,
            max_token_length=2048,
            llama_query_model="gpt-test",
            similarity_top_k=3,
            capability_settings=capability_settings,
        )


def test_index_capability_rejects_missing_retrievers(capability_settings):
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
        capability_settings=capability_settings,
        execution_config=_execution_with_index(),
    )
    with pytest.raises(RetrieverInitError):
        engine.capabilities["index"].get_retrievers()


def test_init_and_get_default_unavailable_metisignore(caplog, capability_settings):
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
        capability_settings=capability_settings,
        metisignore_file=".metisignore_file",
    )
    assert engine.repository.load_metisignore() is None
    assert engine.repository.load_metisignore() is None
    assert not any(
        "MetisIgnore file not loaded" in record.getMessage()
        for record in caplog.records
    )


def test_init_and_get_default_available_metisignore(capability_settings):
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
            capability_settings=capability_settings,
            metisignore_file=temp_file.name,
        )
        assert engine.repository.load_metisignore() is not None
    assert engine is not None


def test_index_capability_initializes_retrievers_once_across_threads(
    capability_settings,
):
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
        capability_settings=capability_settings,
        execution_config=_execution_with_index(),
    )

    results = []
    index = engine.capabilities["index"]

    def _worker():
        results.append(index.get_retrievers())

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results == [("code-retriever", "docs-retriever")] * 8
    backend.init.assert_called_once()
    backend.get_retrievers.assert_called_once()


def test_index_capability_builds_embed_models_lazily_with_usage_callback_manager(
    capability_settings,
):
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
        capability_settings=capability_settings,
        execution_config=_execution_with_index(),
    )

    embedding_provider.get_embed_model_code.assert_not_called()
    embedding_provider.get_embed_model_docs.assert_not_called()

    assert engine.capabilities["index"].get_embedding_models() == (
        code_embed_model,
        docs_embed_model,
    )
    assert embedding_provider.get_embed_model_code.call_args.kwargs == {
        "callback_manager": engine._config.usage_runtime.hooks.callback_manager
    }
    assert embedding_provider.get_embed_model_docs.call_args.kwargs == {
        "callback_manager": engine._config.usage_runtime.hooks.callback_manager
    }
    assert backend.embed_model_code is code_embed_model
    assert backend.embed_model_docs is docs_embed_model


def test_direct_index_api_requests_capability_outside_graph(
    capability_settings: CapabilityRuntimeSettings,
) -> None:
    engine = MetisEngine(
        vector_backend=Mock(),
        llm_provider=Mock(),
        embedding_provider=_embedding_provider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        capability_settings=capability_settings,
    )

    assert "index" not in engine.capabilities
    assert engine.indexing is engine.capabilities.require("index").indexing


def test_engine_closes_capability_after_graph_startup_failure(
    monkeypatch: pytest.MonkeyPatch,
    capability_settings: CapabilityRuntimeSettings,
) -> None:
    backend = Mock()

    def fail_after_index_construction(
        *_args: object,
        capabilities: EngineCapabilities,
        **_kwargs: object,
    ) -> None:
        capabilities["index"]
        raise RuntimeError("invalid graph")

    monkeypatch.setattr(
        "metis.engine.nodes.builtins.ExecutionGraphService",
        fail_after_index_construction,
    )

    with pytest.raises(RuntimeError, match="invalid graph"):
        MetisEngine(
            vector_backend=backend,
            llm_provider=Mock(),
            embedding_provider=_embedding_provider(),
            max_workers=2,
            max_token_length=2048,
            llama_query_model="gpt-test",
            similarity_top_k=3,
            capability_settings=capability_settings,
            execution_config=_execution_with_index(),
        )

    backend.close.assert_called_once_with()


def test_index_tool_exposes_langchain_search_tool(engine, dummy_backend):
    dummy_backend.get_retrievers.reset_mock()

    tools = index_model_tools(
        engine.capabilities["index"],
        engine.capabilities.manifest("index"),
        max_contract_chars=6000,
    )

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
    assert [call.args[1] for call in dummy_backend.get_retrievers.call_args_list] == [
        4,
    ]


def test_memory_service_rejects_paths_outside_codebase(
    tmp_path, dummy_backend, capability_settings
):
    codebase = tmp_path / "repo"
    codebase.mkdir()
    outside = tmp_path / "outside.sqlite3"
    with pytest.raises(ValueError, match="under codebase_path"):
        MetisEngine(
            codebase_path=str(codebase),
            vector_backend=dummy_backend,
            llm_provider=Mock(),
            max_workers=2,
            max_token_length=2048,
            llama_query_model="gpt-test",
            similarity_top_k=3,
            capability_settings=capability_settings,
            memory_config={
                "backend": "sqlite",
                "location": str(outside),
            },
        )


def test_init_codebase_populates_memory_without_index(
    tmp_path, dummy_backend, capability_settings
):
    codebase = tmp_path / "repo"
    codebase.mkdir()
    (codebase / "SECURITY.md").write_text(
        "# Security\n\nFirmware images are untrusted inputs.\n",
        encoding="utf-8",
    )
    engine = MetisEngine(
        codebase_path=str(codebase),
        vector_backend=dummy_backend,
        llm_provider=None,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        capability_settings=capability_settings,
        memory_config={
            "backend": "sqlite",
            "location": "memory.sqlite3",
        },
        threat_model_config={
            "source_patterns": ["SECURITY.*"],
        },
    )
    result = engine.init_codebase()
    assert engine._config.memory_service is not None
    context = engine._config.memory_service.search_records(
        ("repo", "threat_model", "authoritative"),
        query="firmware untrusted",
        limit=3,
    )

    assert "index" not in result
    assert result["threat_model"]["authoritative_sources"] == ["SECURITY.md"]
    assert context
    assert context[0].metadata["binding"] is True


@pytest.mark.parametrize("mode", ["code", "file"])
def test_execute_review_routes_through_default_simple_review_graph(
    engine,
    monkeypatch,
    mode,
):
    review = {
        "file": "test.c",
        "reviews": [
            {
                "issue": "unchecked input",
                "severity": "medium",
                "line_number": 4,
                "suggestion": "validate input",
            }
        ],
    }
    commands = []

    def run_review(_service, command, **_kwargs):
        commands.append(command)
        return ReviewRun(
            ReviewStatus.SUCCEEDED,
            StandardReviewResult.model_validate({"reviews": [review]}),
        )

    monkeypatch.setattr(SimpleLlmReviewService, "run_review", run_review)
    target = str(Path(engine.codebase_path) / "test.c") if mode == "file" else None

    outputs = engine.execute_review(mode, target=target)

    findings = outputs["findings"]["reviews"]
    assert findings[0]["file"] == review["file"]
    finding = dict(findings[0]["reviews"][0])
    assert finding.pop("id")
    assert finding == review["reviews"][0]
    assert outputs["sarif"]["runs"][0]["results"][0]["message"]["text"] == (
        "unchecked input"
    )
    assert commands == [ReviewCommand(mode=mode, target=target)]


def test_explicit_review_producers_run_independently(engine, monkeypatch):
    configuration = ExecutionConfiguration.model_validate(
        {
            "inputs": {"review_request": {"mode": "code"}},
            "stages": {
                "review": {
                    "nodes": {
                        "codegraph": {},
                        "simple_llm_review": {},
                        "reachability": {},
                        "finding_dedup": {},
                        "result": {},
                    }
                }
            },
        }
    )

    def run_review(service, _command, **_kwargs):
        if isinstance(service, ReachabilityReviewService):
            assert service._simple_llm_review is None
            issue = "reachable"
        else:
            issue = "simple"
        return ReviewRun(
            ReviewStatus.SUCCEEDED,
            StandardReviewResult.model_validate(
                {"reviews": [{"file": "test.c", "reviews": [{"issue": issue}]}]}
            ),
        )

    monkeypatch.setattr(SimpleLlmReviewService, "run_review", run_review)
    monkeypatch.setattr(ReachabilityReviewService, "run_review", run_review)
    codegraphs = Mock()
    codegraphs.materialize.return_value = CodeGraphReference(
        revision=1,
        fingerprint="test",
        producer_version="test",
    )
    codegraphs.load.return_value = CodeGraph()
    execution = build_builtin_execution(
        configuration,
        engine_config=engine._config,
        repository=engine.repository,
        capabilities=engine.capabilities,
        codegraphs=codegraphs,
        reachability_settings={},
        triage_options=engine._triage_options,
        triage_checkpoint_every=50,
        review_graph_factory=Mock(),
    ).execution

    result = execution.execute_review(ReviewCommand(mode="code"))

    assert result.status is ExecutionStatus.OK
    assert [
        item.issue
        for group in result.outputs["review"]["findings"].reviews
        for item in group.reviews
    ] == ["simple", "reachable"]


def test_index_search_uses_runtime_capability_config(capability_settings):
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
    configurations = dict(capability_settings.configurations)
    configurations["index"] = {
        "search": {
            "max_top_k": 3,
            "code_top_k": 1,
            "docs_top_k": 2,
            "docs_char_ratio": 0.75,
            "default_max_chars": 40,
            "max_chars": 40,
        }
    }
    capability_settings = replace(capability_settings, configurations=configurations)

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        embedding_provider=_embedding_provider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        capability_settings=capability_settings,
        execution_config=_execution_with_index(),
    )

    result = engine.capabilities["index"].search(
        "allocator ownership", top_k=99, max_chars=99
    )

    assert [call.args[1] for call in backend.get_retrievers.call_args_list] == [1, 2]
    assert result.count("[truncated]") == 2


def test_index_search_can_retrieve_docs_only(capability_settings):
    class _Doc:
        def __init__(self, text):
            self.page_content = text

    code_retriever = Mock(get_relevant_documents=Mock(return_value=[_Doc("code")]))
    docs_retriever = Mock(get_relevant_documents=Mock(return_value=[_Doc("docs")]))
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=(code_retriever, docs_retriever))
    configurations = dict(capability_settings.configurations)
    configurations["index"] = {
        "search": {
            "max_top_k": 1,
            "code_top_k": 1,
            "docs_top_k": 1,
            "docs_char_ratio": 0.7,
            "default_max_chars": 5000,
            "max_chars": 7000,
        }
    }
    capability_settings = replace(capability_settings, configurations=configurations)

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        embedding_provider=_embedding_provider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        capability_settings=capability_settings,
        execution_config=_execution_with_index(),
    )

    result = engine.capabilities["index"].search("trust boundary", source="docs")

    assert "[CODE_CONTEXT]" not in result
    assert "[DOC_CONTEXT]" in result
    assert backend.get_retrievers.call_args.args[1] == 1
    code_retriever.get_relevant_documents.assert_not_called()
    docs_retriever.get_relevant_documents.assert_called_once_with("trust boundary")


def test_navigation_uses_runtime_limits(tmp_path, capability_settings):
    (tmp_path / "sample.txt").write_text("0123456789\n", encoding="utf-8")
    configurations = dict(capability_settings.configurations)
    configurations["navigation"] = {"timeout_seconds": 3, "max_chars": 5}
    capability_settings = replace(capability_settings, configurations=configurations)
    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=Mock(),
        llm_provider=Mock(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        capability_settings=capability_settings,
    )

    assert engine.capabilities["navigation"].cat("sample.txt") == (
        "1: 01\n...[truncated]"
    )


def test_review_graph_uses_usage_callbacks(monkeypatch, capability_settings):
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=("code-retriever", "docs-retriever"))
    llm_provider = Mock()
    llm_provider.get_chat_model.return_value = Mock(with_structured_output=Mock())

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        embedding_provider=_embedding_provider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        capability_settings=capability_settings,
        execution_config=_execution_with_index(),
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
    graph = engine._get_review_graph(engine.capabilities["index"])
    graph._invoke_review_model("system", "body")

    assert (
        captured["chat_model_kwargs"]["callbacks"]
        == engine._config.usage_runtime.hooks.callbacks
    )
    assert [tool.name for tool in captured["model_tools"]] == ["index_search"]
    assert captured["max_tool_rounds"] == 6


@pytest.mark.parametrize("index_first", (False, True))
def test_review_graph_cache_is_scoped_to_the_index_grant(engine, index_first):
    index = engine.capabilities["index"]
    first = engine._get_review_graph(index if index_first else None)
    second = engine._get_review_graph(None if index_first else index)

    graphs = {index_first: first, not index_first: second}
    assert graphs[False].model_tools == ()
    assert [tool.name for tool in graphs[True].model_tools] == ["index_search"]
    assert first is not second


def test_review_graph_cache_is_scoped_to_model(engine):
    first = engine._get_review_graph(model="first-model")
    second = engine._get_review_graph(model="second-model")

    assert first.llama_query_model == "first-model"
    assert second.llama_query_model == "second-model"
    assert first is not second


def test_engine_reuses_injected_runtime_and_backend_embed_models(
    tmp_path, capability_settings
):
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
        capability_settings=capability_settings,
        execution_config=_execution_with_index(),
        usage_runtime=runtime,
    )

    assert engine._config.usage_runtime is runtime
    assert engine.capabilities["index"].get_embedding_models() == (
        backend.embed_model_code,
        backend.embed_model_docs,
    )
    llm_provider.get_chat_model.assert_not_called()


def test_index_prepare_nodes_resets_backend_index_when_supported(
    monkeypatch, capability_settings
):
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
        capability_settings=capability_settings,
    )

    class _Reader:
        def __init__(self, **_kwargs):
            pass

        def load_data(self):
            return []

    monkeypatch.setattr(
        "metis.engine.capabilities.indexing.SimpleDirectoryReader", _Reader
    )
    engine.indexing.index_prepare_nodes()

    embedding_provider.get_embed_model_code.assert_called_once()
    embedding_provider.get_embed_model_docs.assert_called_once()
    backend.init.assert_called_once()
    backend.reset_index.assert_called_once()


def test_index_finalize_embeddings_delegates_node_writes_to_backend(
    capability_settings,
):
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
        capability_settings=capability_settings,
    )
    engine._state.pending_nodes = (["code-node"], ["docs-node"])

    engine.indexing.index_finalize_embeddings()

    backend.index_nodes.assert_called_once_with(
        ["code-node"],
        ["docs-node"],
        embed_model_code=code_embed_model,
        embed_model_docs=docs_embed_model,
        callback_manager=engine._config.usage_runtime.hooks.callback_manager,
    )
    assert engine._state.pending_nodes is None


def test_close_clears_retriever_cache_and_closes_backend(capability_settings):
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
        capability_settings=capability_settings,
        execution_config=_execution_with_index(),
    )

    index = engine.capabilities["index"]
    assert index.get_retrievers() == ("code-retriever", "docs-retriever")
    assert backend.get_retrievers.call_count == 1

    engine.close()

    assert engine._state.retriever_code is None
    assert engine._state.retriever_docs is None
    backend.close.assert_called_once()

    with pytest.raises(RuntimeError, match="cannot schedule new futures"):
        engine.execution._jobs.run(
            [None],
            lambda _value: None,
            label=None,
            result_key=str,
        )

    assert index.get_retrievers() == ("code-retriever", "docs-retriever")
    assert backend.get_retrievers.call_count == 2
