# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace
import threading
from unittest.mock import Mock

import pytest

from llama_index.core import StorageContext, VectorStoreIndex
from llama_index.core.base.embeddings.base import BaseEmbedding
from llama_index.core.callbacks.schema import CBEventType, EventPayload
from llama_index.core.vector_stores import SimpleVectorStore

from metis.engine import MetisEngine
from metis.engine.nodes.simple_llm_review.service import SimpleLlmReviewService
from metis.usage.collector import UsageCollector
from metis.usage.context import current_operation, current_scope, usage_scope
from metis.usage.llamaindex import UsageLlamaIndexHandler
from metis.usage.runtime import UsageRuntime


def test_usage_collector_aggregates_by_scope_model_and_operation():
    collector = UsageCollector()

    collector.record(
        scope_id="review_file:src/a.py",
        operation="review_chunk",
        model="gpt-4o-mini",
        input_tokens=100,
        output_tokens=25,
        total_tokens=125,
    )
    collector.record(
        scope_id="review_file:src/a.py",
        operation="rag_code_query",
        model="gpt-4o-mini",
        input_tokens=40,
        output_tokens=10,
        total_tokens=50,
    )

    total = collector.snapshot()
    scoped = collector.snapshot_scope("review_file:src/a.py")

    assert total["total_tokens"] == 175
    assert total["by_operation"]["review_chunk"]["total_tokens"] == 125
    assert total["by_operation"]["rag_code_query"]["total_tokens"] == 50
    assert total["by_model"]["gpt-4o-mini"]["input_tokens"] == 140
    assert scoped["output_tokens"] == 35


def test_usage_runtime_command_summary_and_persistence(tmp_path, monkeypatch):
    runtime = UsageRuntime(tmp_path)

    with runtime.command("index") as command:
        runtime.langchain_handler.on_llm_end(
            SimpleNamespace(
                llm_output={
                    "model_name": "embed-model",
                    "token_usage": {"prompt_tokens": 80},
                },
                generations=[],
            )
        )

    record = runtime.finalize_command(command)

    assert record["summary"]["total_tokens"] == 80
    assert record["cumulative"]["total_tokens"] == 80

    output_path = Path(runtime.save_run_summary(str(tmp_path / "summary.json")))
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload["totals"]["total_tokens"] == 80
    assert payload["commands"][0]["command_name"] == "index"

    fresh_runtime = UsageRuntime(tmp_path)
    assert fresh_runtime.snapshot_total()["total_tokens"] == 0

    monkeypatch.setattr(
        "metis.json_io.os.replace", Mock(side_effect=OSError("replace failed"))
    )
    with pytest.raises(OSError, match="replace failed"):
        runtime.save_run_summary(str(output_path))
    assert json.loads(output_path.read_text(encoding="utf-8")) == payload
    assert list(tmp_path.iterdir()) == [output_path]


def test_review_code_propagates_usage_context_into_worker_threads(capability_settings):
    backend = Mock()
    backend.init = Mock()
    backend.get_retrievers = Mock(return_value=("code-retriever", "docs-retriever"))

    engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=backend,
        llm_provider=Mock(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        capability_settings=capability_settings,
    )

    files = ["a.py", "b.py"]

    def _review_file(path, **_kwargs):
        engine._config.usage_runtime.collector.record(
            scope_id=current_scope(),
            operation=current_operation(),
            model="gpt-4o-mini",
            input_tokens=5,
            output_tokens=1,
            total_tokens=6,
        )
        return {"file": path}

    service = SimpleLlmReviewService(
        engine._config,
        engine.repository,
        lambda index, model: engine._get_review_graph(index, model),
    )
    service._review_file_standard = _review_file

    with engine.usage_command("review_code") as command:
        results = service.execute_standard_review_with_outcome(
            files,
            jobs=engine.execution._jobs,
        ).result["reviews"]

    record = engine.finalize_usage_command(command)

    assert len(results) == 2
    assert record["summary"]["total_tokens"] == 12
    assert record["summary"]["by_operation"]["review_code"]["input_tokens"] == 10


class _DummyEmbedding(BaseEmbedding):
    def _get_query_embedding(self, query):
        return [0.0]

    async def _aget_query_embedding(self, query):
        return [0.0]

    def _get_text_embedding(self, text):
        return [0.0]

    async def _aget_text_embedding(self, text):
        return [0.0]


class _DummyIndexBackend:
    def __init__(self, embed_model_code, embed_model_docs):
        self.embed_model_code = embed_model_code
        self.embed_model_docs = embed_model_docs
        self.storage_context_code = StorageContext.from_defaults(
            vector_store=SimpleVectorStore()
        )
        self.storage_context_docs = StorageContext.from_defaults(
            vector_store=SimpleVectorStore()
        )

    def init(self):
        return None

    def get_storage_contexts(self):
        return self.storage_context_code, self.storage_context_docs

    def index_nodes(
        self,
        nodes_code,
        nodes_docs,
        *,
        embed_model_code,
        embed_model_docs,
        **embed_model_kwargs,
    ):
        VectorStoreIndex(
            nodes_code,
            storage_context=self.storage_context_code,
            embed_model=embed_model_code,
            **embed_model_kwargs,
        )
        VectorStoreIndex(
            nodes_docs,
            storage_context=self.storage_context_docs,
            embed_model=embed_model_docs,
            **embed_model_kwargs,
        )

    def get_index_handles(
        self,
        *,
        embed_model_code,
        embed_model_docs,
        **embed_model_kwargs,
    ):
        index_code = VectorStoreIndex.from_vector_store(
            self.storage_context_code.vector_store,
            storage_context=self.storage_context_code,
            embed_model=embed_model_code,
            **embed_model_kwargs,
        )
        index_docs = VectorStoreIndex.from_vector_store(
            self.storage_context_docs.vector_store,
            storage_context=self.storage_context_docs,
            embed_model=embed_model_docs,
            **embed_model_kwargs,
        )
        return index_code, index_docs

    def get_retrievers(self, *args, **kwargs):
        return ("code-retriever", "docs-retriever")

    def close(self):
        return None


def test_index_codebase_records_embedding_usage(tmp_path, capability_settings):
    codebase = tmp_path / "repo"
    codebase.mkdir()
    (codebase / "a.py").write_text('print("hello")\n', encoding="utf-8")
    (codebase / "README.md").write_text("# hello\nthis is docs\n", encoding="utf-8")

    runtime = UsageRuntime(codebase)
    backend = _DummyIndexBackend(
        _DummyEmbedding(
            model_name="dummy",
            callback_manager=runtime.hooks.callback_manager,
        ),
        _DummyEmbedding(
            model_name="dummy",
            callback_manager=runtime.hooks.callback_manager,
        ),
    )
    embedding_provider = Mock()
    embedding_provider.get_embed_model_code.return_value = backend.embed_model_code
    embedding_provider.get_embed_model_docs.return_value = backend.embed_model_docs

    engine = MetisEngine(
        codebase_path=str(codebase),
        vector_backend=backend,
        llm_provider=Mock(),
        embedding_provider=embedding_provider,
        usage_runtime=runtime,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        capability_settings=capability_settings,
    )

    with engine.usage_command("index") as command:
        engine.indexing.index_codebase()

    record = engine.finalize_usage_command(command)

    assert record["summary"]["total_tokens"] > 0
    assert record["summary"]["by_operation"]["index"]["input_tokens"] > 0
    assert record["summary"]["by_model"]["dummy"]["input_tokens"] > 0


@pytest.mark.parametrize(
    ("scoped", "payload"),
    [
        (False, {EventPayload.CHUNKS: ["hello"]}),
        (True, None),
        (True, {}),
    ],
)
def test_embedding_event_cleans_pending_model_when_usage_is_skipped(scoped, payload):
    collector = UsageCollector()
    handler = UsageLlamaIndexHandler(collector)
    handler.on_event_start(
        CBEventType.EMBEDDING,
        {EventPayload.MODEL_NAME: "embedding-model"},
        event_id="embedding-event",
    )

    with usage_scope("index") if scoped else nullcontext():
        handler.on_event_end(CBEventType.EMBEDDING, payload, event_id="embedding-event")

    assert handler._embedding_models == {}
    assert collector.snapshot()["total_tokens"] == 0


@pytest.mark.parametrize("callback", ["langchain", "llamaindex"])
@pytest.mark.parametrize(
    "field", ["prompt_tokens", "completion_tokens", "total_tokens"]
)
@pytest.mark.parametrize("value", [float("inf"), float("-inf")])
def test_usage_callbacks_ignore_nonfinite_counts(tmp_path, callback, field, value):
    runtime = UsageRuntime(tmp_path)
    counts = {field: value}
    with runtime.command("inert"):
        if callback == "langchain":
            runtime.langchain_handler.on_llm_end(
                SimpleNamespace(llm_output={"token_usage": counts}, generations=[])
            )
        else:
            runtime.llamaindex_callback_manager.on_event_end(
                CBEventType.LLM,
                {EventPayload.RESPONSE: SimpleNamespace(additional_kwargs=counts)},
            )
    assert runtime.snapshot_total()["total_tokens"] == 0


@pytest.mark.parametrize("access", ["finalize", "completed", "persisted"])
def test_usage_command_returns_do_not_mutate_persisted_records(tmp_path, access):
    runtime = UsageRuntime(tmp_path)
    with runtime.command("inert") as command:
        runtime.collector.record(
            scope_id=command.scope_id,
            operation="inert",
            model="inert",
            input_tokens=1,
            output_tokens=2,
        )
    finalized = runtime.finalize_command(command)
    returned = {
        "finalize": finalized,
        "completed": runtime.completed_commands()[0],
        "persisted": runtime.build_persisted_payload()["commands"][0],
    }[access]
    returned["summary"]["total_tokens"] = 999
    returned["cumulative"]["by_model"]["inert"]["input_tokens"] = 999

    output_path = runtime.save_run_summary(str(tmp_path / "usage.json"))
    payload = json.loads(Path(output_path).read_text(encoding="utf-8"))
    assert payload["commands"][0]["summary"]["total_tokens"] == 3
    assert (
        payload["commands"][0]["cumulative"]["by_model"]["inert"]["input_tokens"] == 1
    )
    assert payload["totals"]["total_tokens"] == 3


@pytest.mark.parametrize(
    ("input_tokens", "output_tokens"), [(-5, 10), (10, -5), (-5, -5)]
)
def test_usage_total_uses_clamped_token_counts(input_tokens, output_tokens):
    collector = UsageCollector()
    collector.record(
        scope_id="scope",
        operation="inert",
        model="inert",
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )
    total = collector.snapshot()
    assert total["input_tokens"] == max(0, input_tokens)
    assert total["output_tokens"] == max(0, output_tokens)
    assert total["total_tokens"] == total["input_tokens"] + total["output_tokens"]
    assert collector.snapshot_scope("scope") == total


def test_concurrent_usage_export_cannot_include_commands_newer_than_totals(
    tmp_path, monkeypatch
):
    runtime = UsageRuntime(tmp_path)
    original_snapshot = runtime.snapshot_total
    snapshot_taken = threading.Event()
    command_done = threading.Event()
    exporting_thread = threading.get_ident()

    def paused_snapshot():
        result = original_snapshot()
        if threading.get_ident() == exporting_thread:
            snapshot_taken.set()
            assert command_done.wait(timeout=5)
        return result

    monkeypatch.setattr(runtime, "snapshot_total", paused_snapshot)

    def complete_command():
        assert snapshot_taken.wait(timeout=5)
        with runtime.command("inert") as command:
            runtime.collector.record(
                scope_id=command.scope_id,
                operation="inert",
                model="inert",
                input_tokens=1,
                output_tokens=2,
            )
        runtime.finalize_command(command)
        command_done.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(complete_command)
        output_path = runtime.save_run_summary(str(tmp_path / "usage.json"))
        future.result(timeout=5)

    payload = json.loads(Path(output_path).read_text(encoding="utf-8"))
    command_tokens = sum(
        item["summary"]["total_tokens"] for item in payload["commands"]
    )
    assert payload["totals"]["total_tokens"] >= command_tokens
    assert runtime.completed_commands()[0]["summary"]["total_tokens"] == 3
