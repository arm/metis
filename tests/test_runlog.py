# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import CancelledError
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.callbacks import CallbackManager
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableLambda

from metis.engine import MetisEngine
from metis.engine.concurrency import JobScheduler
from metis.engine.execution import ExecutionResult
from metis.engine.execution import ExecutionStatus
from metis.engine.execution.catalog import NodeCatalog
from metis.engine.execution.compiler import compile_stage
from metis.engine.execution.contracts import NodeCallbacks
from metis.engine.execution.contracts import NodeContext
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.execution.contracts import NodeRuntime
from metis.engine.execution.graph import StageConfiguration
from metis.engine.execution.runner import run_stage
from metis.engine.llm_runner import JsonPromptRequest
from metis.engine.llm_runner import JsonPromptRunner
from metis.engine.model_tool_runner import invoke_model_with_tools
from metis.execution_nodes import EmptyNodeConfiguration
from metis.runlog.langchain import RUNLOG_CALLBACK_HANDLER
from metis.runlog.langchain import RunLogCallbackHandler
from metis.runlog.langchain import ensure_runlog_callback

from metis import runlog


def _records(session: runlog.RunLogSession) -> list[dict]:
    return [
        json.loads(line)
        for line in session.ndjson_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _exact_config(tmp_path: Path, **kwargs) -> runlog.RunLogConfig:
    return runlog.RunLogConfig(path=tmp_path / "trace.ndjson", **kwargs)


def test_disabled_helpers_do_not_evaluate_lazy_attributes(tmp_path):
    evaluated = False

    def attributes():
        nonlocal evaluated
        evaluated = True
        return {"path": tmp_path}

    with runlog.span("task", attributes=attributes):
        runlog.event("progress", attributes)

    assert evaluated is False
    assert list(tmp_path.iterdir()) == []


def test_session_writes_v1_root_lifecycle_and_meta(tmp_path):
    session = runlog.open_runlog(
        _exact_config(tmp_path),
        metadata={"command": "review", "api_key": "secret-value"},
    )
    with session:
        assert runlog.current_runlog() is session
        runlog.event("ready", {"value": 1})

    records = _records(session)
    assert [record["seq"] for record in records] == list(range(len(records)))
    assert records[0]["record"] == "span.start"
    assert records[0]["kind"] == "run"
    assert records[0]["parent_span_id"] is None
    assert records[-1]["record"] == "span.end"
    assert records[-1]["span_id"] == records[0]["span_id"]
    assert records[-1]["status"] == "ok"
    assert runlog.SCHEMA_VERSION == 1
    assert all(record["v"] == runlog.SCHEMA_VERSION for record in records)
    assert len({record["record_id"] for record in records}) == len(records)
    assert all(record["explanation"].strip() for record in records)
    assert records[0]["explanation"] == records[-1]["explanation"]

    meta = json.loads(session.meta_path.read_text(encoding="utf-8"))
    assert meta["complete"] is True
    assert meta["status"] == "ok"
    assert meta["metadata"]["api_key"]["$redacted"] is True
    assert runlog.current_runlog() is None


def test_span_hierarchy_and_point_event_identity(tmp_path):
    with runlog.open_runlog(_exact_config(tmp_path)) as session:
        with runlog.span(
            "command",
            "review",
            explanation="The review of one user-selected target.",
        ) as command:
            with runlog.span("stage", "review") as stage:
                with runlog.span("task", "Reachability security review") as review:
                    review.event(
                        "progress",
                        {
                            "event": "reachability_frontier_review_start",
                            "nodes": 59,
                        },
                    )

    records = _records(session)
    command_start = next(
        record
        for record in records
        if record["record"] == "span.start" and record.get("kind") == "command"
    )
    stage_start = next(
        record
        for record in records
        if record["record"] == "span.start" and record.get("kind") == "stage"
    )
    review_start = next(
        record
        for record in records
        if record["record"] == "span.start"
        and record.get("name") == "Reachability security review"
    )
    progress = next(record for record in records if record["record"] == "event")

    assert command_start["parent_span_id"] == session.root_span_id
    assert stage_start["parent_span_id"] == command_start["span_id"]
    assert review_start["parent_span_id"] == stage_start["span_id"]
    assert progress["span_id"] == review_start["span_id"]
    assert "parent_span_id" not in progress
    assert progress["record_id"] != progress["span_id"]
    assert command_start["explanation"] == "The review of one user-selected target."
    assert stage_start["explanation"] == (
        "One configured initialize, review, or triage stage executed as part of "
        "the workflow."
    )
    assert review_start["explanation"] == (
        "One batch of functions reviewed with deterministic CodeGraph evidence."
    )
    assert progress["explanation"] == (
        "Reachability security review began for the selected functions and "
        "deterministic CodeGraph evidence."
    )
    assert command.span_id != stage.span_id != review.span_id


def test_exception_closes_span_and_run_as_error(tmp_path):
    session = runlog.open_runlog(_exact_config(tmp_path))
    with pytest.raises(ValueError, match="boom"):
        with session:
            with runlog.span("task", "failing"):
                raise ValueError("boom")

    records = _records(session)
    task_end = next(
        record
        for record in records
        if record["record"] == "span.end" and record.get("kind") == "task"
    )
    assert task_end["status"] == "error"
    assert task_end["error"]["type"] == "ValueError"
    assert task_end["error"]["message"] == "boom"
    assert records[-1]["kind"] == "run"
    assert records[-1]["status"] == "error"


def test_large_text_and_structured_payloads_use_atomic_blobs(tmp_path):
    config = _exact_config(tmp_path, blob_threshold=48)
    with runlog.open_runlog(config) as session:
        runlog.event(
            "payload",
            {
                "prompt": "A" * 100,
                "state": {"items": [f"item-{index}" for index in range(20)]},
                "config": {
                    "model": "test",
                    "access_token": "top-secret",
                    "client_secret": "client-secret",
                    "private_key": "private-key",
                    "headers": {"cookie": "session=secret"},
                },
            },
        )
        runlog.event("duplicate", {"prompt": "A" * 100})

    records = _records(session)
    payload = next(record for record in records if record["name"] == "payload")
    duplicate = next(record for record in records if record["name"] == "duplicate")
    prompt_ref = payload["attributes"]["prompt"]
    state_ref = payload["attributes"]["state"]
    config_value = payload["attributes"]["config"]

    assert prompt_ref["$ref"] == duplicate["attributes"]["prompt"]["$ref"]
    assert (session.output_dir / prompt_ref["$ref"]).read_text() == "A" * 100
    assert json.loads((session.output_dir / state_ref["$ref"]).read_text())["items"]
    if "$ref" in config_value:
        config_value = json.loads(
            (session.output_dir / config_value["$ref"]).read_text(encoding="utf-8")
        )
    assert config_value["access_token"]["$redacted"] is True
    assert config_value["client_secret"]["$redacted"] is True
    assert config_value["private_key"]["$redacted"] is True
    headers_value = config_value["headers"]
    if "$ref" in headers_value:
        headers_value = json.loads(
            (session.output_dir / headers_value["$ref"]).read_text(encoding="utf-8")
        )
    assert headers_value["cookie"]["$redacted"] is True
    assert (
        sum(
            path.name == Path(prompt_ref["$ref"]).name
            for path in session.blobs_dir.iterdir()
        )
        == 1
    )


def test_metadata_mode_hashes_but_does_not_write_content(tmp_path):
    config = _exact_config(tmp_path, content="metadata", blob_threshold=16)
    with runlog.open_runlog(config) as session:
        runlog.event("payload", {"prompt": "sensitive source text" * 4})

    payload = next(
        record for record in _records(session) if record["name"] == "payload"
    )
    reference = payload["attributes"]["prompt"]
    assert reference["$omitted"] is True
    assert "$ref" not in reference
    assert not session.blobs_dir.exists()


def test_concurrent_writes_preserve_authoritative_line_order(tmp_path):
    with runlog.open_runlog(_exact_config(tmp_path)) as session:

        def worker(worker_id: int):
            for index in range(100):
                session.event("tick", {"worker": worker_id, "index": index})

        threads = [
            threading.Thread(target=worker, args=(worker_id,)) for worker_id in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    records = _records(session)
    ticks = [record for record in records if record["name"] == "tick"]
    assert len(ticks) == 800
    assert [record["seq"] for record in records] == list(range(len(records)))
    assert len({record["record_id"] for record in records}) == len(records)


def test_explicit_ndjson_path_is_never_appended(tmp_path):
    config = _exact_config(tmp_path)
    with runlog.open_runlog(config):
        pass
    original = config.path.read_bytes()

    with pytest.raises(FileExistsError):
        with runlog.open_runlog(config):
            pass
    assert config.path.read_bytes() == original


def test_execution_runner_traces_tolerated_failure_under_stage(tmp_path):
    def fail(_invocation):
        runlog.event("node.custom", {"value": "inside"})
        raise RuntimeError("failed")

    registrations = (
        NodeRegistration(
            "failure",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": str},
            fail,
        ),
        NodeRegistration(
            "success",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": str},
            lambda _invocation: NodeResult({"value": "available"}),
        ),
        NodeRegistration(
            "collector",
            "initialize",
            EmptyNodeConfiguration,
            {"values": tuple[str, ...]},
            {"values": tuple[str, ...]},
            lambda invocation: NodeResult({"values": invocation.inputs["values"]}),
        ),
    )
    stage = StageConfiguration.model_validate(
        {"nodes": {"failure": {}, "success": {}, "collector": {}}}
    )
    plan = compile_stage(NodeCatalog(registrations, ()), "initialize", stage, {}, {})
    progress: list[dict[str, object]] = []
    context = NodeContext(
        stage="initialize",
        codebase_path=".",
        repository=object(),
        capabilities={},
        prompts=object(),
        codegraphs=object(),
        runtime=NodeRuntime("test", 1, 1000, {}, 1, jobs=Mock()),
        callbacks=NodeCallbacks(progress=progress.append),
    )

    with runlog.open_runlog(_exact_config(tmp_path)) as session:
        result = run_stage("initialize", plan, context, {})

    records = _records(session)
    stage_start = next(
        record
        for record in records
        if record["record"] == "span.start" and record.get("kind") == "stage"
    )
    failure_start = next(
        record
        for record in records
        if record["record"] == "span.start"
        and record.get("name") == "initialize.failure"
    )
    custom = next(record for record in records if record["name"] == "node.custom")
    node_statuses = {
        record["name"]: record["status"]
        for record in records
        if record["record"] == "span.end" and record.get("kind") == "node"
    }
    stage_end = next(
        record
        for record in records
        if record["record"] == "span.end" and record.get("kind") == "stage"
    )
    assert result.status is ExecutionStatus.INCONCLUSIVE
    assert result.outputs["collector"] == ("available",)
    assert stage_end["status"] == "inconclusive"
    assert node_statuses == {
        "initialize.failure": "error",
        "initialize.success": "ok",
        "initialize.collector": "ok",
    }
    assert (
        next(event for event in progress if event["event"] == "execution_stage_end")[
            "status"
        ]
        == "inconclusive"
    )
    assert failure_start["parent_span_id"] == stage_start["span_id"]
    assert custom["span_id"] == failure_start["span_id"]
    runlog.validate_runlog(session.ndjson_path)


def test_parallel_jobs_are_traced_with_compact_keys(tmp_path):
    scheduler = JobScheduler(2)
    try:
        with runlog.open_runlog(_exact_config(tmp_path)) as session:
            results = scheduler.limit(2).run(
                [2, 3],
                lambda value: value * value,
                label="Reachability security review",
                result_key=lambda value: value,
            )
    finally:
        scheduler.close()

    assert sorted(results) == [4, 9]
    tasks = [
        record
        for record in _records(session)
        if record["record"] == "span.start" and record.get("kind") == "task"
    ]
    assert {record["name"] for record in tasks} == {"Reachability security review"}
    assert {record["attributes"]["key"] for record in tasks} == {2, 3}
    assert all(record["parent_span_id"] == session.root_span_id for record in tasks)
    runlog.validate_runlog(session.ndjson_path)


def test_scheduler_accepts_none_jobs_without_losing_worker_capacity() -> None:
    scheduler = JobScheduler(1)
    with ThreadPoolExecutor(max_workers=1) as caller:
        try:
            result = caller.submit(
                scheduler.limit(1).run,
                [None, 2],
                lambda value: value,
                label=None,
                result_key=str,
            )
            assert result.result(timeout=2) == [None, 2]
        finally:
            scheduler.close()


def test_scheduler_shares_global_workers_across_node_limits() -> None:
    scheduler = JobScheduler(2)
    state_lock = threading.Lock()
    active = 0
    peak = 0

    def work(value: int) -> int:
        nonlocal active, peak
        with state_lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.02)
        with state_lock:
            active -= 1
        return value

    try:
        jobs = scheduler.limit(2)
        with ThreadPoolExecutor(max_workers=2) as callers:
            first = callers.submit(
                jobs.run,
                [1, 2, 3],
                work,
                label=None,
                result_key=str,
            )
            second = callers.submit(
                jobs.run,
                [4, 5, 6],
                work,
                label=None,
                result_key=str,
            )
            assert sorted((*first.result(), *second.result())) == [1, 2, 3, 4, 5, 6]
    finally:
        scheduler.close()

    assert peak == 2


def test_scheduler_limit_one_bounds_submissions_and_runs_off_coordinator() -> None:
    scheduler = JobScheduler(2)
    first_started = threading.Event()
    second_started = threading.Event()
    release_first = threading.Event()
    coordinator: list[int] = []
    workers: list[int] = []

    def work(value: int) -> int:
        workers.append(threading.get_ident())
        if value == 1:
            first_started.set()
            release_first.wait(timeout=2)
        else:
            second_started.set()
        return value

    def run() -> list[int]:
        coordinator.append(threading.get_ident())
        return scheduler.limit(1).run(
            [1, 2],
            work,
            label=None,
            result_key=str,
        )

    try:
        with ThreadPoolExecutor(max_workers=1) as caller:
            result = caller.submit(run)
            try:
                assert first_started.wait(timeout=1)
                second_was_blocked = not second_started.wait(timeout=0.1)
            finally:
                release_first.set()
            assert result.result() == [1, 2]
    finally:
        scheduler.close()

    assert second_was_blocked
    assert second_started.is_set()
    assert all(worker != coordinator[0] for worker in workers)


def test_scheduler_gives_a_new_run_the_next_available_worker() -> None:
    scheduler = JobScheduler(2)
    first_started = threading.Event()
    second_started = threading.Event()
    third_started = threading.Event()
    other_started = threading.Event()
    release_first = threading.Event()
    release_second = threading.Event()
    release_other = threading.Event()

    def first_work(value: int) -> int:
        if value == 1:
            first_started.set()
            release_first.wait(timeout=2)
        elif value == 2:
            second_started.set()
            release_second.wait(timeout=2)
        else:
            third_started.set()
        return value

    def other_work(value: int) -> int:
        other_started.set()
        release_other.wait(timeout=2)
        return value

    try:
        with ThreadPoolExecutor(max_workers=2) as callers:
            first = callers.submit(
                scheduler.limit(2).run,
                [1, 2, 3],
                first_work,
                label=None,
                result_key=str,
            )
            assert first_started.wait(timeout=1)
            assert second_started.wait(timeout=1)
            other = callers.submit(
                scheduler.limit(2).run,
                [4],
                other_work,
                label=None,
                result_key=str,
            )
            assert not other_started.wait(timeout=0.05)
            release_first.set()
            assert other_started.wait(timeout=1)
            assert not third_started.is_set()
            release_second.set()
            release_other.set()
            assert sorted(first.result()) == [1, 2, 3]
            assert other.result() == [4]
    finally:
        release_first.set()
        release_second.set()
        release_other.set()
        scheduler.close()


def test_scheduler_does_not_replenish_before_a_failure_is_collected() -> None:
    scheduler = JobScheduler(2)
    allow_failure = threading.Event()
    failure_started = threading.Event()
    failure_finished = threading.Event()
    collecting = threading.Event()
    release_collector = threading.Event()
    extra_started = threading.Event()

    def work(value: int) -> int:
        if value == 0:
            failure_started.wait(timeout=2)
            return value
        if value == 1:
            failure_started.set()
            allow_failure.wait(timeout=2)
            failure_finished.set()
            raise RuntimeError("terminal")
        extra_started.set()
        return value

    def on_complete(_value: int, _completed: int, _total: int) -> None:
        collecting.set()
        release_collector.wait(timeout=2)

    try:
        with ThreadPoolExecutor(max_workers=2) as callers:
            failed = callers.submit(
                scheduler.limit(2).run,
                [0, 1, 2, 3],
                work,
                label=None,
                result_key=str,
                on_complete=on_complete,
            )
            assert collecting.wait(timeout=1)
            allow_failure.set()
            assert failure_finished.wait(timeout=1)
            other = callers.submit(
                scheduler.limit(2).run,
                [4],
                lambda value: value,
                label=None,
                result_key=str,
            )
            assert other.result() == [4]
            assert not extra_started.is_set()
            release_collector.set()
            with pytest.raises(RuntimeError, match="terminal"):
                failed.result()
    finally:
        allow_failure.set()
        release_collector.set()
        scheduler.close()


def test_scheduler_cancellation_does_not_spin_or_start_queued_jobs() -> None:
    scheduler = JobScheduler(2)
    cancellation = threading.Event()
    jobs = scheduler.limit(2).with_cancellation(cancellation)
    release = threading.Event()
    two_started = threading.Event()
    state_lock = threading.Lock()
    started = 0
    wait_calls = 0
    wait_for = scheduler._condition.wait_for

    def tracked_wait_for(predicate, timeout=None):
        nonlocal wait_calls
        wait_calls += 1
        return wait_for(predicate, timeout)

    scheduler._condition.wait_for = tracked_wait_for

    def work(value: int) -> int:
        nonlocal started
        with state_lock:
            started += 1
            if started == 2:
                two_started.set()
        release.wait(timeout=2)
        return value

    try:
        with ThreadPoolExecutor(max_workers=1) as caller:
            result = caller.submit(
                jobs.run,
                list(range(20)),
                work,
                label=None,
                result_key=str,
            )
            assert two_started.wait(timeout=1)
            jobs.cancel()
            time.sleep(0.05)
            assert wait_calls < 10
            release.set()
            with pytest.raises(CancelledError):
                result.result()
    finally:
        release.set()
        scheduler.close()

    assert started == 2


def test_prompt_retry_records_logical_attempts(tmp_path):
    class Provider:
        def get_chat_model(self, **_kwargs):
            return RunnableLambda(lambda _messages: AIMessage(content="not-json"))

    request = JsonPromptRequest(
        model="test-model",
        system_prompt="system",
        user_prompt="user {value}",
        variables={"value": "input"},
        parse=lambda _raw: None,
        logger=__import__("logging").getLogger("metis.test.runlog"),
        label="Retry prompt",
        batch_size=1,
        invalid_message="invalid",
        final_keep_message="giving up",
    )

    with runlog.open_runlog(_exact_config(tmp_path)) as session:
        result = JsonPromptRunner(
            Provider(), max_attempts=2, retry_backoff_seconds=0
        ).invoke(request)

    assert result is None
    records = _records(session)
    prompts = [
        record
        for record in records
        if record["record"] == "span.start" and record.get("kind") == "prompt"
    ]
    attempts = [
        record
        for record in records
        if record["record"] == "span.start" and record.get("kind") == "attempt"
    ]
    retries = [record for record in records if record["name"] == "retry"]
    assert len(prompts) == 1
    assert len(attempts) == 2
    assert len(retries) == 1
    assert all(
        attempt["parent_span_id"] == prompts[0]["span_id"] for attempt in attempts
    )


def test_langchain_callback_records_physical_call_and_usage(tmp_path):
    handler = RunLogCallbackHandler()
    response = type(
        "Response",
        (),
        {
            "llm_output": {},
            "generations": [
                [
                    SimpleNamespace(
                        usage_metadata={"input_tokens": 7, "output_tokens": 3},
                        response_metadata={"model_name": " fake-model "},
                    )
                ]
            ],
        },
    )()

    with runlog.open_runlog(_exact_config(tmp_path)) as session:
        handler.on_chat_model_start(
            {"name": "fake-chat"},
            [[AIMessage(content="request")]],
            run_id="call-1",
            invocation_params={"model": "fake-model"},
        )
        handler.on_llm_end(response, run_id="call-1")

    records = _records(session)
    call_start = next(
        record
        for record in records
        if record["record"] == "span.start" and record.get("kind") == "llm.call"
    )
    usage = next(record for record in records if record["name"] == "usage")
    assert usage["span_id"] == call_start["span_id"]
    assert usage["attributes"]["model"] == "fake-model"
    assert usage["attributes"]["total_tokens"] == 10
    assert session.counters["llm_calls"] == 1
    assert session.counters["total_tokens"] == 10


def test_callback_manager_receives_runlog_handler_once():
    manager = CallbackManager([])

    assert ensure_runlog_callback(manager) is manager
    assert ensure_runlog_callback(manager) is manager
    assert manager.handlers.count(RUNLOG_CALLBACK_HANDLER) == 1
    assert manager.inheritable_handlers.count(RUNLOG_CALLBACK_HANDLER) == 1


def test_model_tool_loop_records_tool_span(tmp_path):
    class Tool:
        name = "lookup"

        def invoke(self, args):
            return f"result:{args['query']}"

    class ToolChat:
        def __init__(self):
            self.calls = 0

        def invoke(self, _messages):
            self.calls += 1
            if self.calls == 1:
                return AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "lookup",
                            "args": {"query": "needle"},
                            "id": "tool-1",
                            "type": "tool_call",
                        }
                    ],
                )
            return AIMessage(content="final")

    class Chat:
        def __init__(self):
            self.tool_chat = ToolChat()

        def bind_tools(self, _tools):
            return self.tool_chat

    prompt = ChatPromptTemplate.from_messages([("user", "{question}")])
    with runlog.open_runlog(_exact_config(tmp_path)) as session:
        result, evidence = invoke_model_with_tools(
            Chat(),
            prompt,
            {"question": "find it"},
            (Tool(),),
            max_tool_rounds=2,
        )

    assert result == "final"
    assert evidence
    records = _records(session)
    loop = next(
        record
        for record in records
        if record["record"] == "span.start" and record.get("kind") == "model_loop"
    )
    tool = next(
        record
        for record in records
        if record["record"] == "span.start" and record.get("kind") == "tool"
    )
    assert tool["parent_span_id"] == loop["span_id"]
    assert session.counters["tool_calls"] == 1


def test_engine_api_preserves_command_parentage(tmp_path):
    engine = object.__new__(MetisEngine)
    engine.execution = SimpleNamespace(
        execute_graph=lambda **_kwargs: ExecutionResult(
            ExecutionStatus.OK,
            {"review": {"value": "done"}},
            (),
        )
    )

    with runlog.open_runlog(_exact_config(tmp_path)) as session:
        engine._runlog = session
        with runlog.span("command", "programmatic") as command:
            result = engine.execute_graph()

    assert result.outputs == {"review": {"value": "done"}}
    execution = next(
        record
        for record in _records(session)
        if record["record"] == "span.start" and record.get("kind") == "execution"
    )
    assert execution["parent_span_id"] == command.span_id


def test_validator_accepts_complete_trace_and_blobs(tmp_path):
    with runlog.open_runlog(_exact_config(tmp_path, blob_threshold=16)) as session:
        runlog.event("payload", {"text": "large content" * 20})

    summary = runlog.validate_runlog(session.ndjson_path)
    assert summary.run_id == session.run_id
    assert summary.records == len(_records(session))
    assert summary.spans == 1
    assert summary.events == 1
    assert summary.blobs >= 1
    assert summary.status == "ok"


def test_ended_span_rejects_new_activity(tmp_path):
    with runlog.open_runlog(_exact_config(tmp_path)):
        task = runlog.span("task", "finished")
        task.end()
        with pytest.raises(RuntimeError, match="ended run-log span"):
            task.event("late")
        with pytest.raises(RuntimeError, match="ended run-log span"):
            with task.activate():
                pass


def test_validator_rejects_event_after_containing_span_ended(tmp_path):
    with runlog.open_runlog(_exact_config(tmp_path)) as session:
        task = session.span("task", "finished")
        task.end()
        session.event("late", span_id=task.span_id)

    with pytest.raises(runlog.TraceValidationError, match="open containing span"):
        runlog.validate_runlog(session.ndjson_path)


def test_validator_rejects_parent_ending_before_child(tmp_path):
    with runlog.open_runlog(_exact_config(tmp_path)) as session:
        parent = session.span("task", "parent")
        child = session.span("task", "child", parent_span_id=parent.span_id)
        parent.end()
        child.end()

    with pytest.raises(runlog.TraceValidationError, match="child spans ended first"):
        runlog.validate_runlog(session.ndjson_path)


def test_validator_rejects_incomplete_metadata(tmp_path):
    with runlog.open_runlog(_exact_config(tmp_path)) as session:
        pass
    metadata = json.loads(session.meta_path.read_text(encoding="utf-8"))
    metadata["complete"] = False
    session.meta_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(runlog.TraceValidationError, match="complete metadata"):
        runlog.validate_runlog(session.ndjson_path)


def test_runtime_write_failure_disables_logging_without_failing_run(tmp_path):
    class BrokenFile:
        def __init__(self, delegate):
            self.delegate = delegate

        def write(self, _value):
            raise OSError("disk unavailable")

        def flush(self):
            raise OSError("disk unavailable")

        def close(self):
            self.delegate.close()

    with runlog.open_runlog(_exact_config(tmp_path)) as session:
        session._file = BrokenFile(session._file)
        runlog.event("unwritable", {"value": 1})
        assert session.enabled is False

    meta = json.loads(session.meta_path.read_text(encoding="utf-8"))
    assert meta["complete"] is False


def test_runlog_preserves_existing_output_directory_permissions(tmp_path):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    output_dir.chmod(0o750)

    with runlog.open_runlog(
        runlog.RunLogConfig(path=output_dir / "run.ndjson")
    ) as session:
        assert output_dir.stat().st_mode & 0o777 == 0o750
        assert session.ndjson_path.stat().st_mode & 0o777 == 0o600
        assert session.meta_path.stat().st_mode & 0o777 == 0o600
