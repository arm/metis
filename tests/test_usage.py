# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path
from unittest.mock import Mock

from llama_index.core import StorageContext
from llama_index.core.base.embeddings.base import BaseEmbedding
from llama_index.core.vector_stores import SimpleVectorStore

from metis.engine import MetisEngine
from metis.usage.collector import UsageCollector
from metis.usage.context import current_operation, current_scope
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


def test_usage_runtime_command_summary_and_persistence(tmp_path):
    runtime = UsageRuntime(tmp_path)

    with runtime.command("index") as command:
        runtime.collector.record(
            scope_id=command.scope_id,
            operation="index",
            model="embed-model",
            input_tokens=80,
            output_tokens=0,
            total_tokens=80,
        )

    record = runtime.finalize_command(command)

    assert record["summary"]["total_tokens"] == 80
    assert record["cumulative"]["total_tokens"] == 80

    output_path = Path(runtime.save_run_summary())
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload["totals"]["total_tokens"] == 80
    assert payload["commands"][0]["command_name"] == "index"

    fresh_runtime = UsageRuntime(tmp_path)
    assert fresh_runtime.snapshot_total()["total_tokens"] == 0


def test_review_code_propagates_usage_context_into_worker_threads():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()

    engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    engine.get_code_files = lambda: ["a.py", "b.py"]

    def _review_file(path):
        engine.usage_runtime.collector.record(
            scope_id=current_scope(),
            operation=current_operation(),
            model="gpt-4o-mini",
            input_tokens=5,
            output_tokens=1,
            total_tokens=6,
        )
        return {"file": path}

    engine.review_file = _review_file

    with engine.usage_command("review_code") as command:
        results = list(engine.review_code())

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

    def get_query_engines(self, *args, **kwargs):
        return ("code-qe", "docs-qe")

    def close(self):
        return None


def test_index_codebase_records_embedding_usage(tmp_path):
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

    engine = MetisEngine(
        codebase_path=str(codebase),
        vector_backend=backend,
        llm_provider=Mock(),
        usage_runtime=runtime,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    with engine.usage_command("index") as command:
        engine.index_codebase()

    record = engine.finalize_usage_command(command)

    assert record["summary"]["total_tokens"] > 0
    assert record["summary"]["by_operation"]["index"]["input_tokens"] > 0
    assert record["summary"]["by_model"]["dummy"]["input_tokens"] > 0
