# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import threading
from collections import UserString
from collections.abc import Mapping
from collections.abc import Sequence
from concurrent.futures import CancelledError
from dataclasses import dataclass
import time
from dataclasses import replace
from typing import Any
from typing import Annotated
from typing import Literal
from typing import NewType
from typing import Tuple
from unittest.mock import Mock
from unittest.mock import sentinel

import pytest
from pydantic import BaseModel
from pydantic import AfterValidator
from pydantic import ConfigDict
from pydantic import ValidationError
from pydantic import Field
from pydantic import PrivateAttr
from pydantic import field_validator

from metis.configuration import load_execution_config
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphReference
from metis.engine.concurrency import JobScheduler
from metis.engine.execution import ExecutionStatus
from metis.engine.execution.catalog import NodeCatalog
from metis.engine.execution.compiler import StagePlan
from metis.engine.execution.compiler import compile_stage
from metis.engine.execution.graph import StageConfiguration
from metis.engine.execution.runner import run_stage
from metis.engine.nodes.codegraph import registration as codegraph_node
from metis.engine.nodes.finding_dedup import registration as finding_dedup_node
from metis.engine.nodes.index import registration as index_node
from metis.engine.nodes.reachability import review as reachability_review_node
from metis.engine.nodes.result import review as review_results_node
from metis.engine.nodes.result import triage as triage_results_node
from metis.engine.nodes.simple_llm_review import registration as review_node
from metis.engine.nodes.threat_model import registration as threat_model_node
from metis.engine.nodes.triage import registration as triage_node
from metis.engine.stages.configuration import ExecutionConfiguration
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import ReviewStatus
from metis.engine.stages.review.models import StandardReviewResult
from metis.engine.stages.service import ExecutionGraphService
from metis.engine.stages.triage.models import TriageRun
from metis.engine.source import ProfiledSourceReference
from metis.execution_nodes import CapabilityRequirement
from metis.execution_nodes import EmptyNodeConfiguration
from metis.execution_nodes import ExecutionDiagnostic
from metis.execution_nodes import NodeCallbacks
from metis.execution_nodes import NodeContext
from metis.execution_nodes import NodeInvocation
from metis.execution_nodes import NodeRegistration
from metis.execution_nodes import NodeResult
from metis.execution_nodes import NodeRuntime
from metis.execution_nodes import ReviewCommand
from metis.runtime_settings import TriageOptions


class _Jobs:
    def __init__(self) -> None:
        self.limits: list[int] = []

    def limit(self, max_concurrency: int):
        self.limits.append(max_concurrency)
        return self

    def with_cancellation(self, _cancellation):
        return self

    def cancel(self):
        return None

    def run(self, jobs, worker, **_kwargs):
        return [worker(job) for job in jobs]


def _configuration() -> ExecutionConfiguration:
    return ExecutionConfiguration.model_validate(
        {
            "inputs": {
                "review_request": {"mode": "code"},
            },
            "stages": {
                "initialize": {
                    "outputs": {
                        "threat_model": "threat_model.threat_model",
                        "codegraph": "codegraph.codegraph",
                    },
                    "nodes": {
                        "threat_model": {"capabilities": ["memory"]},
                        "codegraph": {},
                    },
                },
                "review": {
                    "inputs": {"codegraph": "initialize.codegraph"},
                    "nodes": {
                        "simple_llm_review": {"capabilities": ["index", "memory"]},
                        "finding_dedup": {},
                        "result": {
                            "formats": ["sarif", "json"],
                        },
                    },
                },
                "triage": {
                    "inputs": {
                        "sarif": "review.sarif",
                        "codegraph": "initialize.codegraph",
                    },
                    "nodes": {
                        "triage": {"capabilities": ["memory", "navigation"]},
                        "result": {
                            "formats": ["sarif"],
                        },
                    },
                },
            },
        }
    )


def _review_run(
    status: ReviewStatus = ReviewStatus.SUCCEEDED,
) -> ReviewRun:
    return ReviewRun(
        status,
        StandardReviewResult.model_validate(
            {"reviews": [{"reviews": [{"issue": "reachable"}]}]}
        ),
    )


def _findings_run(*findings: dict[str, object]) -> ReviewRun:
    return ReviewRun(
        ReviewStatus.SUCCEEDED,
        StandardReviewResult.model_validate(
            {"reviews": [{"file": "src/example.c", "reviews": list(findings)}]}
        ),
    )


def test_builtin_stage_order_is_stable_when_yaml_is_reordered() -> None:
    configuration = ExecutionConfiguration.model_validate(
        {
            "inputs": {"review_request": {"mode": "code"}},
            "stages": {
                "review": {
                    "inputs": {"codegraph": "initialize.codegraph"},
                    "nodes": {"result": {}},
                },
                "initialize": {
                    "outputs": {"codegraph": "init.codegraph"},
                    "nodes": {"init": {}},
                },
            },
        }
    )

    assert configuration.stage_order() == ("initialize", "review")


def test_simple_review_does_not_require_codegraph() -> None:
    raw = _configuration().model_dump(mode="json")
    raw["stages"] = {"review": raw["stages"]["review"]}
    raw["stages"]["review"]["inputs"] = {}
    raw["stages"]["review"]["nodes"]["result"]["formats"] = ["sarif"]

    _service(ExecutionConfiguration.model_validate(raw))


def test_reachability_requires_typed_codegraph_input() -> None:
    configuration = ExecutionConfiguration.model_validate(
        {
            "inputs": {"review_request": {"mode": "code"}},
            "stages": {
                "review": {
                    "nodes": {"reachability": {}, "result": {"formats": ["sarif"]}}
                }
            },
        }
    )

    with pytest.raises(ValueError, match="unbound inputs: codegraph"):
        _service(configuration)


def test_reachability_rejects_unavailable_codegraph_producer() -> None:
    raw = _configuration().model_dump(mode="json")
    raw["stages"]["review"]["nodes"]["reachability"] = {
        "inputs": {"codegraph": "producer.codegraph"}
    }
    configuration = ExecutionConfiguration.model_validate(raw)

    with pytest.raises(ValueError, match="unavailable nodes: producer"):
        _service(configuration)


def test_reachability_accepts_explicit_review_stage_codegraph_binding() -> None:
    raw = _configuration().model_dump(mode="json")
    raw["stages"]["review"]["nodes"]["reachability"] = {
        "inputs": {"codegraph": "$inputs.codegraph"}
    }

    _service(ExecutionConfiguration.model_validate(raw))


def test_profiled_codegraph_infers_required_profile_dependency() -> None:
    raw = _configuration().model_dump(mode="json")
    raw["stages"]["initialize"]["nodes"]["custom_profile"] = {}
    profile = NodeRegistration(
        "custom_profile",
        "initialize",
        EmptyNodeConfiguration,
        {},
        {"profiled_source": ProfiledSourceReference},
        lambda _invocation: NodeResult({}, ExecutionStatus.ERROR),
    )
    service, calls = _service(
        ExecutionConfiguration.model_validate(raw),
        extra_registrations=(profile,),
    )
    try:
        result = service.execute_initialize()

        assert result.status is ExecutionStatus.ERROR
        assert "codegraph" not in calls
    finally:
        service.close()


def test_finding_dedup_combines_producers_before_result() -> None:
    prompt_runner = Mock()
    prompt_runner.invoke.side_effect = lambda request: request.parse(
        {
            "groups": [
                {
                    "member_indexes": [0, 1],
                    "representative_index": 1,
                    "relationship": "duplicate",
                    "reason": "same unchecked copy",
                }
            ]
        }
    )
    context = replace(
        _node_context(),
        stage="review",
        prompts=prompt_runner,
        runtime=NodeRuntime(
            "test",
            2,
            1000,
            {},
            1,
            lambda _text: 1,
            jobs=_Jobs(),
        ),
    )

    result = finding_dedup_node.execute(
        NodeInvocation(
            EmptyNodeConfiguration(),
            {
                "reviews": (
                    _findings_run(
                        {
                            "issue": "Unchecked copy",
                            "line_number": 12,
                            "reasoning": "length reaches memcpy unchecked",
                        }
                    ),
                    _findings_run(
                        {
                            "issue": "Unchecked length reaches copy",
                            "line_number": 12,
                            "reasoning": "length reaches memcpy unchecked",
                        }
                    ),
                )
            },
            context,
        )
    )

    finalized = result.outputs["review"].review
    assert [
        finding.issue for group in finalized.result.reviews for finding in group.reviews
    ] == ["Unchecked length reaches copy"]


def test_finding_dedup_fails_open_when_batch_exceeds_global_limit() -> None:
    prompt_runner = Mock()
    context = replace(
        _node_context(),
        stage="review",
        prompts=prompt_runner,
        runtime=NodeRuntime(
            "test",
            1,
            10,
            {},
            1,
            lambda _text: 100,
            jobs=_Jobs(),
        ),
    )
    result = finding_dedup_node.execute(
        NodeInvocation(
            EmptyNodeConfiguration(),
            {
                "reviews": (
                    _findings_run({"issue": "First report"}),
                    _findings_run({"issue": "Second report"}),
                )
            },
            context,
        )
    )

    finalized = result.outputs["review"].review
    assert sum(len(group.reviews) for group in finalized.result.reviews) == 2
    prompt_runner.invoke.assert_not_called()


def test_finding_dedup_keeps_candidates_when_model_returns_no_decision() -> None:
    prompt_runner = Mock()
    prompt_runner.invoke.return_value = None
    result = finding_dedup_node.execute(
        NodeInvocation(
            EmptyNodeConfiguration(),
            {
                "reviews": (
                    _findings_run({"issue": "First report"}),
                    _findings_run({"issue": "Second report"}),
                )
            },
            replace(_node_context(), stage="review", prompts=prompt_runner),
        )
    )

    finalized = result.outputs["review"].review
    assert sum(len(group.reviews) for group in finalized.result.reviews) == 2


def test_finding_dedup_removes_exact_duplicates_without_model() -> None:
    prompt_runner = Mock()
    prompt_runner.invoke.return_value = None

    result = finding_dedup_node.execute(
        NodeInvocation(
            EmptyNodeConfiguration(),
            {
                "reviews": (
                    _findings_run({"issue": "Same report"}),
                    _findings_run({"issue": "Same report"}),
                )
            },
            replace(_node_context(), stage="review", prompts=prompt_runner),
        )
    )

    finalized = result.outputs["review"].review
    assert sum(len(group.reviews) for group in finalized.result.reviews) == 1
    prompt_runner.invoke.assert_not_called()


def _node_context() -> NodeContext:
    return NodeContext(
        stage="initialize",
        codebase_path=".",
        repository=Mock(),
        capabilities={},
        prompts=Mock(),
        codegraphs=Mock(),
        runtime=NodeRuntime(
            "test",
            1,
            1000,
            {},
            1,
            lambda _text: 1,
            jobs=_Jobs(),
        ),
        callbacks=NodeCallbacks(),
    )


@pytest.mark.parametrize("max_concurrency", (0, -1, True, "2"))
def test_node_max_concurrency_requires_a_strict_positive_integer(
    max_concurrency: object,
) -> None:
    with pytest.raises(ValidationError):
        StageConfiguration.model_validate(
            {"nodes": {"node": {"max_concurrency": max_concurrency}}}
        )


@pytest.mark.parametrize(
    ("configured", "expected"),
    ((None, 2), (1, 1), (3, 2)),
)
def test_node_max_concurrency_caps_runtime_limit(
    configured: int | None,
    expected: int,
) -> None:
    registration = NodeRegistration(
        "node",
        "initialize",
        EmptyNodeConfiguration,
        {},
        {"workers": int},
        lambda invocation: NodeResult(
            {"workers": invocation.context.runtime.max_workers}
        ),
    )
    node = {} if configured is None else {"max_concurrency": configured}
    stage = StageConfiguration.model_validate(
        {"outputs": ["node"], "nodes": {"node": node}}
    )
    context = replace(
        _node_context(),
        runtime=NodeRuntime(
            "test",
            2,
            1000,
            {},
            1,
            lambda _text: 1,
            jobs=_Jobs(),
        ),
    )

    result = run_stage(
        "initialize",
        _compile((registration,), stage),
        context,
        {},
    )

    assert result.outputs == {"node": expected}
    assert context.jobs.limits == [expected]


def test_node_model_overrides_runtime_and_token_counter() -> None:
    received: list[tuple[str, int]] = []
    registration = NodeRegistration(
        "node",
        "initialize",
        EmptyNodeConfiguration,
        {},
        {},
        lambda invocation: (
            received.append(
                (
                    invocation.context.runtime.model,
                    invocation.context.runtime.token_counter("prompt"),
                )
            )
            or NodeResult({})
        ),
    )
    stage = StageConfiguration.model_validate(
        {"nodes": {"node": {"model": "node-model"}}}
    )
    context = _node_context()
    context = replace(
        context,
        runtime=replace(
            context.runtime,
            token_counter_for_model=lambda model: lambda text: len(model + text),
        ),
    )

    result = run_stage(
        "initialize",
        _compile((registration,), stage),
        context,
        {},
    )

    assert result.status is ExecutionStatus.OK
    assert received == [("node-model", len("node-modelprompt"))]


def test_node_model_must_not_be_blank() -> None:
    with pytest.raises(ValidationError, match="model must not be blank"):
        StageConfiguration.model_validate({"nodes": {"node": {"model": " "}}})


def test_ready_nodes_run_as_dependencies_complete() -> None:
    simple_started = threading.Event()
    reachability_started = threading.Event()
    events: list[dict[str, object]] = []

    def run_simple(_invocation: NodeInvocation) -> NodeResult:
        simple_started.set()
        assert reachability_started.wait(timeout=2)
        return NodeResult({"value": "simple"})

    def build_codegraph(_invocation: NodeInvocation) -> NodeResult:
        assert simple_started.wait(timeout=2)
        return NodeResult({"value": "codegraph"})

    def run_reachability(invocation: NodeInvocation) -> NodeResult:
        reachability_started.set()
        assert invocation.context.callbacks.progress is not None
        invocation.context.callbacks.progress({"event": "reachability_work"})
        return NodeResult({"value": "reachability"})

    registrations = tuple(
        NodeRegistration(
            name,
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": str},
            execute,
        )
        for name, execute in (
            ("simple", run_simple),
            ("codegraph", build_codegraph),
            ("reachability", run_reachability),
        )
    )
    stage = StageConfiguration.model_validate(
        {
            "nodes": {
                "simple": {},
                "codegraph": {},
                "reachability": {"depends_on": ["codegraph"]},
            }
        }
    )
    context = replace(
        _node_context(),
        callbacks=NodeCallbacks(progress=events.append),
        runtime=NodeRuntime(
            "test",
            2,
            1000,
            {},
            1,
            lambda _text: 1,
            jobs=_Jobs(),
        ),
    )

    result = run_stage(
        "initialize",
        _compile(registrations, stage),
        context,
        {},
    )

    assert result.status is ExecutionStatus.OK
    assert tuple(result.outputs) == ("simple", "codegraph", "reachability")
    assert (
        next(event for event in events if event["event"] == "reachability_work")["node"]
        == "reachability"
    )


def test_stage_interrupt_cancels_queued_node_jobs() -> None:
    scheduler = JobScheduler(2)
    two_started = threading.Event()
    state_lock = threading.Lock()
    started = 0

    def work(value: int) -> int:
        nonlocal started
        with state_lock:
            started += 1
            if started == 2:
                two_started.set()
        threading.Event().wait(timeout=0.2)
        return value

    def run_jobs(invocation: NodeInvocation) -> NodeResult:
        values = invocation.context.jobs.run(
            list(range(20)),
            work,
            label=None,
            result_key=str,
        )
        return NodeResult({"value": str(len(values))})

    def interrupt(_invocation: NodeInvocation) -> NodeResult:
        assert two_started.wait(timeout=1)
        raise KeyboardInterrupt

    registrations = (
        NodeRegistration(
            "jobs",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": str},
            run_jobs,
        ),
        NodeRegistration(
            "interrupt",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": str},
            interrupt,
        ),
    )
    stage = StageConfiguration.model_validate({"nodes": {"jobs": {}, "interrupt": {}}})
    context = replace(
        _node_context(),
        runtime=replace(
            _node_context().runtime,
            max_workers=2,
            jobs=scheduler.limit(2),
        ),
    )

    try:
        with pytest.raises(KeyboardInterrupt):
            run_stage(
                "initialize",
                _compile(registrations, stage),
                context,
                {},
            )
    finally:
        scheduler.close()

    assert started == 2


def test_stage_interrupt_signals_running_node_progress() -> None:
    scheduler = JobScheduler(1)
    started = threading.Event()

    def run_until_cancelled(invocation: NodeInvocation) -> NodeResult:
        started.set()
        for _iteration in range(2_000):
            invocation.context.report_progress({"event": "work"})
            threading.Event().wait(timeout=0.001)
        return NodeResult({"value": "timed-out"})

    def interrupt(_invocation: NodeInvocation) -> NodeResult:
        assert started.wait(timeout=1)
        raise KeyboardInterrupt

    registrations = (
        NodeRegistration(
            "work",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": str},
            run_until_cancelled,
        ),
        NodeRegistration(
            "interrupt",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": str},
            interrupt,
        ),
    )
    stage = StageConfiguration.model_validate({"nodes": {"work": {}, "interrupt": {}}})
    base_context = _node_context()
    context = replace(
        base_context,
        runtime=replace(
            base_context.runtime,
            max_workers=2,
            jobs=scheduler.limit(1),
        ),
    )

    started_at = time.monotonic()
    try:
        with pytest.raises(KeyboardInterrupt):
            run_stage(
                "initialize",
                _compile(registrations, stage),
                context,
                {},
            )
    finally:
        scheduler.close()

    assert time.monotonic() - started_at < 1


def _value_node(name: str, value: str) -> NodeRegistration:
    return NodeRegistration(
        name,
        "initialize",
        EmptyNodeConfiguration,
        {},
        {"value": str},
        lambda _invocation: NodeResult({"value": value}),
    )


def _compile(
    registrations: tuple[NodeRegistration, ...],
    stage: StageConfiguration,
    capabilities: dict[str, object] | None = None,
) -> StagePlan:
    return compile_stage(
        NodeCatalog(registrations, ()),
        "initialize",
        stage,
        {},
        {},
        capabilities,
    )


def _service(
    configuration: ExecutionConfiguration | None = None,
    *,
    entry_points: tuple[Any, ...] = (),
    extra_registrations: tuple[NodeRegistration, ...] = (),
    review_run: ReviewRun | None = None,
    review_commands: list[ReviewCommand] | None = None,
    triage_options: TriageOptions | None = None,
    triage_runs: list[TriageRun] | None = None,
) -> tuple[ExecutionGraphService, list[object]]:
    calls: list[object] = []
    engine_config = Mock(
        codebase_path=".",
        llm_provider=Mock(count_tokens=lambda _text, model=None: 1),
        llama_query_model="test",
        max_workers=2,
        max_active_nodes=2,
        max_concurrent_executions=2,
        max_token_length=1000,
        chat_model_kwargs={},
    )
    indexing = Mock()
    indexing.index_codebase.side_effect = lambda: calls.append("index")
    index = Mock(indexing=indexing)
    reference = CodeGraphReference(
        revision=1,
        fingerprint="test",
        producer_version="test",
    )
    codegraphs = Mock()
    codegraphs.materialize.side_effect = lambda *_args, **_kwargs: (
        calls.append("codegraph") or reference
    )
    codegraphs.load.return_value = CodeGraph()
    review = Mock()

    def run_review(command, **_kwargs):
        calls.append("review")
        if review_commands is not None:
            review_commands.append(command)
        return review_run or _review_run()

    review.run_review.side_effect = run_review
    triage = Mock()
    triage_classifier = Mock()

    def triage_run(run, *, classifier, **_kwargs):
        if triage_runs is not None:
            triage_runs.append(run)
        calls.append("triage")
        return replace(run, remaining=(), processed=run.total)

    triage.triage_run.side_effect = triage_run
    initialized_threat_model = threat_model_node.InitializedThreatModelResult(
        status="ok",
        records_written=0,
        records_deleted=0,
        authoritative_sources=[],
    )
    threat_model_registration = NodeRegistration(
        "threat_model",
        "initialize",
        EmptyNodeConfiguration,
        {},
        {"threat_model": threat_model_node.InitializedThreatModelResult},
        lambda _invocation: NodeResult({"threat_model": initialized_threat_model}),
        {"memory": CapabilityRequirement.REQUIRED},
    )
    service = ExecutionGraphService(
        configuration or _configuration(),
        engine_config=engine_config,
        repository=Mock(),
        capabilities={
            "index": index,
            "memory": Mock(),
            "navigation": Mock(),
        },
        prompt_runner=Mock(),
        codegraphs=codegraphs,
        triage_adjudicator=triage,
        triage_options=triage_options or TriageOptions(),
        registrations=(
            threat_model_registration,
            index_node.registration,
            codegraph_node.registration,
            review_node.create_node(review),
            reachability_review_node.create_node(review),
            finding_dedup_node,
            review_results_node.registration,
            triage_node.create_node(triage_classifier),
            triage_results_node.registration,
            *extra_registrations,
        ),
        entry_points=entry_points,
    )
    return service, calls


def test_configured_include_triaged_can_be_overridden_per_run() -> None:
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "message": {"text": "already handled"},
                        "properties": {"metisTriaged": True},
                    }
                ]
            }
        ],
    }
    runs: list[TriageRun] = []
    service, _ = _service(
        triage_options=TriageOptions(include_triaged=True),
        triage_runs=runs,
    )

    service.execute_triage(payload)
    service.execute_triage(payload, include_triaged=False)

    assert [run.total for run in runs] == [1, 0]


def test_default_graph_runs_fixed_stages_and_passes_review_sarif():
    configuration = ExecutionConfiguration.model_validate(load_execution_config())
    service, calls = _service(configuration)

    result = service.execute_graph()

    assert result.status is ExecutionStatus.OK
    assert calls == ["codegraph", "review", "review", "triage"]
    assert tuple(result.outputs) == ("initialize", "review", "triage")
    assert result.outputs["triage"]["sarif"] == result.outputs["review"]["sarif"]


@pytest.mark.parametrize(
    "stage_inputs",
    ({}, {"codegraph": "$inputs.codegraph"}),
    ids=("omitted", "unset-execution-input"),
)
def test_required_external_review_input_must_be_configured(stage_inputs) -> None:
    raw = _configuration().model_dump(mode="json")
    raw["stages"]["review"]["inputs"] = stage_inputs
    raw["stages"]["review"]["nodes"]["requires_graph"] = {}
    configuration = ExecutionConfiguration.model_validate(raw)
    requires_graph = NodeRegistration(
        "requires_graph",
        "review",
        EmptyNodeConfiguration,
        {"codegraph": CodeGraphReference},
        {},
        lambda _invocation: NodeResult({}),
    )

    with pytest.raises(ValueError, match="unbound inputs: codegraph"):
        _service(configuration, extra_registrations=(requires_graph,))


def test_required_review_input_rejects_nullable_stage_output() -> None:
    raw = _configuration().model_dump(mode="json")
    raw["stages"]["initialize"]["outputs"]["codegraph"] = "maybe.codegraph"
    raw["stages"]["initialize"]["nodes"]["maybe"] = {}
    del raw["stages"]["initialize"]["nodes"]["codegraph"]
    raw["stages"]["review"]["nodes"]["reachability"] = {}
    maybe = NodeRegistration(
        "maybe",
        "initialize",
        EmptyNodeConfiguration,
        {},
        {"codegraph": CodeGraphReference | None},
        lambda _invocation: NodeResult({"codegraph": None}),
    )

    with pytest.raises(ValueError, match="input 'codegraph' is incompatible"):
        _service(
            ExecutionConfiguration.model_validate(raw),
            extra_registrations=(maybe,),
        )


def test_direct_review_skips_unrelated_initialize_stage() -> None:
    raw = _configuration().model_dump(mode="json")
    raw["stages"]["review"]["inputs"] = {}
    configuration = ExecutionConfiguration.model_validate(raw)
    service, calls = _service(configuration)

    result = service.execute_review(ReviewCommand(mode="code"))

    assert result.status is ExecutionStatus.OK
    assert calls == ["review"]


def test_profiled_codegraph_fails_when_source_graph_is_incomplete():
    codegraphs = Mock()
    codegraphs.materialize.return_value = CodeGraphReference(
        revision=1,
        fingerprint="fingerprint",
        producer_version="test",
        failed_files=("source.c",),
    )
    context = replace(_node_context(), stage="initialize", codegraphs=codegraphs)
    context.repository.profiled_source_fingerprint = "profile"
    context.repository.source_profile_applies_to_path.side_effect = lambda path: (
        path.endswith(".c")
    )
    profile = ProfiledSourceReference(
        fingerprint="profile",
        compile_commands_path="compile_commands.json",
        compile_commands_sha256="0" * 64,
        translation_units=1,
        source_views=1,
        profiled_files=1,
        ambiguous_files=0,
        active_line_count=1,
    )
    invocation = NodeInvocation(
        EmptyNodeConfiguration(), {"profiled_source": profile}, context
    )

    with pytest.raises(RuntimeError, match="contains failed files"):
        codegraph_node.registration.execute(invocation)

    codegraphs.materialize.return_value = (
        codegraphs.materialize.return_value.model_copy(
            update={"failed_files": ("module.py",)},
        )
    )
    result = codegraph_node.registration.execute(invocation)
    assert result.outputs["codegraph"].failed_files == ("module.py",)

    for installed in (None, "different-profile"):
        context.repository.profiled_source_fingerprint = installed
        codegraphs.materialize.reset_mock()
        with pytest.raises(RuntimeError, match="does not match the installed profile"):
            codegraph_node.registration.execute(invocation)
        codegraphs.materialize.assert_not_called()


def test_inconclusive_review_still_feeds_triage():
    service, calls = _service(
        review_run=_review_run(ReviewStatus.INCONCLUSIVE),
    )

    result = service.execute_graph()

    assert result.status is ExecutionStatus.INCONCLUSIVE
    assert calls[-1] == "triage"


def test_results_keep_sarif_in_memory_when_no_file_formats_are_requested():
    raw = _configuration().model_dump(mode="json")
    raw["stages"]["review"]["nodes"]["result"]["formats"] = []
    service, _calls = _service(ExecutionConfiguration.model_validate(raw))

    result = service.execute_review(ReviewCommand(mode="code"))

    results = result.outputs["review"]
    assert results["formats"] == ()
    assert results["sarif"].version == "2.1.0"


def test_result_publishes_configured_filename():
    raw = _configuration().model_dump(mode="json")
    raw["stages"]["review"]["nodes"]["result"]["filename"] = "results/review"
    service, _calls = _service(ExecutionConfiguration.model_validate(raw))

    result = service.execute_review(ReviewCommand(mode="code"))

    assert result.outputs["review"]["filename"] == "results/review"


def test_filename_belongs_to_the_result_node():
    raw = _configuration().model_dump(mode="json")
    node = raw["stages"]["review"]["nodes"]["simple_llm_review"]
    node["formats"] = ["json"]
    node["filename"] = "results/review"

    with pytest.raises(ValueError, match="configured on its result node"):
        ExecutionConfiguration.model_validate(raw)


def test_patch_review_publishes_the_canonical_codegraph_reference():
    commands = []
    service, calls = _service(review_commands=commands)
    command = ReviewCommand(mode="patch", target="changes.patch")

    result = service.execute_review(command)

    assert calls == ["codegraph", "review"]
    assert commands == [command]
    assert result.outputs["review"]["codegraph"].fingerprint == "test"


def test_failed_review_stops_before_triage():
    service, calls = _service(
        review_run=ReviewRun(ReviewStatus.FAILED, None),
    )

    result = service.execute_graph()

    assert result.status is ExecutionStatus.ERROR
    assert "triage" not in calls
    assert tuple(result.outputs) == ("initialize",)


def test_third_party_sarif_runs_initialize_then_triage():
    sarif = {"version": "2.1.0", "runs": [{"results": []}]}
    configuration = ExecutionConfiguration.model_validate(
        {
            "inputs": {"sarif": sarif},
            "stages": {
                "initialize": {
                    "outputs": ["index"],
                    "nodes": {"index": {"capabilities": ["index"]}},
                },
                "triage": {
                    "depends_on": ["initialize"],
                    "inputs": {"sarif": "$inputs.sarif"},
                    "nodes": {
                        "triage": {"capabilities": ["memory", "navigation"]},
                        "result": {
                            "formats": ["sarif"],
                        },
                    },
                },
            },
        }
    )
    service, calls = _service(configuration)

    result = service.execute_graph()

    assert result.status is ExecutionStatus.OK
    assert calls == ["index", "triage"]


def test_optional_execution_input_may_be_unset():
    configuration = ExecutionConfiguration.model_validate(
        {
            "inputs": {"sarif": {"version": "2.1.0", "runs": []}},
            "stages": {
                "triage": {
                    "inputs": {
                        "sarif": "$inputs.sarif",
                        "codegraph": "$inputs.codegraph",
                    },
                    "nodes": {"result": {"formats": ["sarif"]}},
                }
            },
        }
    )

    assert configuration.inputs.codegraph is None


def test_required_execution_input_must_be_configured():
    with pytest.raises(
        ValueError,
        match="Execution input 'sarif' is required by triage",
    ):
        ExecutionConfiguration.model_validate(
            {
                "stages": {
                    "triage": {
                        "inputs": {"sarif": "$inputs.sarif"},
                        "nodes": {"result": {"formats": ["sarif"]}},
                    }
                }
            }
        )


def test_execution_input_binding_must_match_stage_contract():
    with pytest.raises(
        ValueError,
        match=r"Execution stage 'triage' input 'codegraph' is incompatible",
    ):
        ExecutionConfiguration.model_validate(
            {
                "inputs": {"sarif": {"version": "2.1.0", "runs": []}},
                "stages": {
                    "triage": {
                        "inputs": {
                            "sarif": "$inputs.sarif",
                            "codegraph": "$inputs.sarif",
                        },
                        "nodes": {"result": {"formats": ["sarif"]}},
                    }
                },
            }
        )


def test_initialize_stage_requires_explicit_outputs():
    configuration = ExecutionConfiguration.model_validate(
        {"stages": {"initialize": {"nodes": {"index": {"capabilities": ["index"]}}}}}
    )

    with pytest.raises(ValueError, match="initialize.*must declare outputs"):
        _service(configuration)


def test_implicit_stage_output_requires_a_terminal_result():
    raw = _configuration().model_dump(mode="json")
    raw["stages"]["review"]["nodes"]["simple_llm_review"]["depends_on"] = ["result"]

    with pytest.raises(ValueError, match="terminal result has dependants"):
        _service(ExecutionConfiguration.model_validate(raw))


def test_node_dependency_cycle_is_rejected():
    registrations = (
        _value_node("first", "ok"),
        NodeRegistration(
            "second",
            "initialize",
            EmptyNodeConfiguration,
            {"value": str},
            {"value": str},
            lambda invocation: NodeResult({"value": invocation.inputs["value"]}),
        ),
    )
    stage = StageConfiguration.model_validate(
        {
            "nodes": {
                "first": {"depends_on": ["second"]},
                "second": {
                    "inputs": {"value": "first"},
                },
            }
        }
    )

    with pytest.raises(ValueError, match="contains a cycle"):
        _compile(registrations, stage)


@pytest.mark.parametrize(
    ("configured", "match"),
    (
        ((), "requires capabilities: memory"),
        (("navigation",), "does not declare capabilities: navigation"),
    ),
)
def test_node_capability_contract_is_validated(
    configured: tuple[str, ...],
    match: str,
) -> None:
    registration = NodeRegistration(
        "private_node",
        "initialize",
        EmptyNodeConfiguration,
        {},
        {},
        lambda _invocation: NodeResult({}),
        {
            "memory": CapabilityRequirement.REQUIRED,
            "index": CapabilityRequirement.OPTIONAL,
        },
    )
    stage = StageConfiguration(
        nodes={
            "private_node": {
                "capabilities": configured,
            }
        }
    )

    with pytest.raises(ValueError, match=match):
        compile_stage(
            NodeCatalog((registration,), ()),
            "initialize",
            stage,
            {},
            {},
            {"memory": object(), "index": object(), "navigation": object()},
        )


def test_node_receives_only_its_configured_capabilities() -> None:
    received: list[set[str]] = []
    registration = NodeRegistration(
        "private_node",
        "initialize",
        EmptyNodeConfiguration,
        {},
        {},
        lambda invocation: (
            received.append(set(invocation.context.capabilities)) or NodeResult({})
        ),
        {
            "memory": CapabilityRequirement.OPTIONAL,
            "index": CapabilityRequirement.OPTIONAL,
        },
    )
    stage = StageConfiguration.model_validate(
        {"nodes": {"private_node": {"capabilities": ["index"]}}}
    )
    capabilities = {"memory": object(), "index": object()}
    run_stage(
        "initialize",
        _compile((registration,), stage, capabilities),
        _node_context(),
        {},
    )

    assert received == [{"index"}]


def test_node_failure_skips_dependants_but_runs_independent_nodes():
    events: list[dict[str, object]] = []
    diagnostic_seen = threading.Event()

    def fail(_invocation):
        raise RuntimeError("failed")

    def run_independent(_invocation: NodeInvocation) -> NodeResult:
        assert diagnostic_seen.wait(timeout=2)
        return NodeResult({"value": "ran"})

    registrations = (
        NodeRegistration(
            "failure",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {},
            fail,
        ),
        _value_node("dependant", "not-run"),
        NodeRegistration(
            "independent",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": str},
            run_independent,
        ),
    )
    stage = StageConfiguration.model_validate(
        {
            "nodes": {
                "failure": {},
                "dependant": {"depends_on": ["failure"]},
                "independent": {},
            }
        }
    )
    plan = _compile(registrations, stage)

    context = _node_context()
    context = replace(
        context,
        runtime=replace(context.runtime, max_workers=2),
        callbacks=NodeCallbacks(
            progress=events.append,
            diagnostic=lambda _diagnostic: diagnostic_seen.set(),
        ),
    )
    result = run_stage("initialize", plan, context, {})

    assert result.status is ExecutionStatus.ERROR
    assert tuple(result.outputs) == ("independent",)
    assert result.diagnostics == (
        ExecutionDiagnostic(
            "execution.node_failed",
            "Execution node initialize.failure failed: failed",
        ),
    )
    assert events[0]["event"] == "execution_stage_start"
    assert events[-1]["event"] == "execution_stage_end"
    node_statuses = {
        str(event["node"]): event["status"]
        for event in events
        if event["event"] == "execution_node_end"
    }
    assert node_statuses == {"failure": "error", "independent": "ok"}
    skipped = next(
        event for event in events if event["event"] == "execution_node_skipped"
    )
    assert skipped == {
        "event": "execution_node_skipped",
        "stage": "initialize",
        "node": "dependant",
        "reason": "dependency_failed",
    }
    assert events[-1]["status"] == "error"
    assert all(
        event["duration_seconds"] >= 0
        for event in events
        if "duration_seconds" in event
    )


@pytest.mark.parametrize(
    "status",
    (ExecutionStatus.OK, ExecutionStatus.INCONCLUSIVE, ExecutionStatus.ERROR),
)
def test_lifecycle_end_events_report_node_and_stage_status(
    status: ExecutionStatus,
) -> None:
    events: list[dict[str, object]] = []
    registration = NodeRegistration(
        name="status_node",
        stage="initialize",
        configuration=EmptyNodeConfiguration,
        inputs={},
        outputs={"value": str},
        execute=lambda _invocation: NodeResult(
            {} if status is ExecutionStatus.ERROR else {"value": "done"},
            status=status,
        ),
    )
    stage = StageConfiguration.model_validate({"nodes": {"status_node": {}}})
    plan = _compile((registration,), stage)
    context = replace(
        _node_context(),
        callbacks=NodeCallbacks(progress=events.append),
    )

    result = run_stage("initialize", plan, context, {})

    assert result.status is status
    assert events[-2]["event"] == "execution_node_end"
    assert events[-2]["status"] == status.value
    assert events[-1]["event"] == "execution_stage_end"
    assert events[-1]["status"] == status.value


@pytest.mark.parametrize("outputs", ({}, {"value": 1}))
def test_invalid_private_node_output_fails_and_skips_dependant(
    outputs: dict[str, object],
) -> None:
    registrations = (
        NodeRegistration(
            "producer",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": str},
            lambda _invocation: NodeResult(outputs),
        ),
        NodeRegistration(
            "consumer",
            "initialize",
            EmptyNodeConfiguration,
            {"value": str},
            {"result": str},
            lambda invocation: NodeResult({"result": invocation.inputs["value"]}),
        ),
    )
    stage = StageConfiguration.model_validate(
        {
            "nodes": {
                "producer": {},
                "consumer": {"inputs": {"value": "producer"}},
            }
        }
    )
    result = run_stage(
        "initialize",
        _compile(registrations, stage),
        _node_context(),
        {},
    )

    assert result.status is ExecutionStatus.ERROR
    assert result.outputs == {}
    assert result.diagnostics[0].code == "execution.node_failed"


def test_multi_output_reference_requires_an_output_name():
    registrations = (
        NodeRegistration(
            "producer",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"left": str, "right": str},
            lambda _invocation: NodeResult({"left": "a", "right": "b"}),
        ),
        NodeRegistration(
            "consumer",
            "initialize",
            EmptyNodeConfiguration,
            {"value": str},
            {"value": str},
            lambda invocation: NodeResult({"value": invocation.inputs["value"]}),
        ),
    )
    stage = StageConfiguration.model_validate(
        {
            "nodes": {
                "producer": {},
                "consumer": {"inputs": {"value": "producer"}},
            }
        }
    )

    with pytest.raises(ValueError, match="must select one"):
        _compile(registrations, stage)


def test_explicit_input_resolves_an_implicit_binding_ambiguity():
    registrations = (
        _value_node("first", "first"),
        _value_node("second", "second"),
        NodeRegistration(
            "consumer",
            "initialize",
            EmptyNodeConfiguration,
            {"value": str},
            {"value": str},
            lambda invocation: NodeResult({"value": invocation.inputs["value"]}),
        ),
    )
    ambiguous = StageConfiguration.model_validate(
        {"nodes": {"first": {}, "second": {}, "consumer": {}}}
    )

    with pytest.raises(ValueError, match="matches multiple outputs"):
        _compile(registrations, ambiguous)

    explicit = StageConfiguration.model_validate(
        {
            "nodes": {
                "first": {},
                "second": {},
                "consumer": {"inputs": {"value": "first"}},
            }
        }
    )
    plan = _compile(registrations, explicit)
    result = run_stage("initialize", plan, _node_context(), {})

    assert result.outputs["consumer"] == "first"


@pytest.mark.parametrize(
    ("bindings", "source_annotation", "target_annotation", "value", "expected"),
    (
        ({}, Any, Any, sentinel.value, sentinel.value),
        ({}, tuple[str, ...], tuple[str, ...], (), ()),
        ({"values": "$inputs.values"}, tuple[str, ...], tuple[str, ...], (), ()),
        (
            {},
            tuple[str, ...],
            tuple[str, ...],
            ("first", "second"),
            ("first", "second"),
        ),
        ({"values": ["$inputs.values"]}, str, tuple[str, ...], "first", ("first",)),
    ),
)
def test_stage_inputs_preserve_any_and_tuple_values(
    bindings, source_annotation, target_annotation, value, expected
):
    registration = NodeRegistration(
        "echo",
        "initialize",
        EmptyNodeConfiguration,
        {"values": target_annotation},
        {"values": target_annotation},
        lambda invocation: NodeResult({"values": invocation.inputs["values"]}),
    )
    stage = StageConfiguration.model_validate({"nodes": {"echo": {"inputs": bindings}}})
    plan = compile_stage(
        NodeCatalog((registration,), ()),
        "initialize",
        stage,
        {},
        {"values": source_annotation},
    )

    result = run_stage("initialize", plan, _node_context(), {"values": value})

    assert result.status is ExecutionStatus.OK
    assert result.outputs["echo"] == expected


@pytest.mark.parametrize(
    ("bindings", "target_annotation"),
    (
        ({"values": "$inputs.values"}, tuple[str, ...]),
        ({"values": ["$inputs.values"]}, str),
    ),
)
def test_stage_inputs_reject_scalar_and_collection_mismatches(
    bindings, target_annotation
):
    registration = NodeRegistration(
        "echo",
        "initialize",
        EmptyNodeConfiguration,
        {"values": target_annotation},
        {"values": target_annotation},
        lambda invocation: NodeResult({"values": invocation.inputs["values"]}),
    )
    stage = StageConfiguration.model_validate({"nodes": {"echo": {"inputs": bindings}}})

    with pytest.raises(ValueError, match="incompatible|multiple sources"):
        compile_stage(
            NodeCatalog((registration,), ()),
            "initialize",
            stage,
            {},
            {"values": str},
        )


def test_collection_input_collects_all_compatible_producers():
    registrations = (
        _value_node("second", "second"),
        _value_node("first", "first"),
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
        {"nodes": {"second": {}, "first": {}, "collector": {}}}
    )

    result = run_stage(
        "initialize",
        _compile(registrations, stage),
        _node_context(),
        {},
    )

    assert result.outputs["collector"] == ("second", "first")


def test_collection_input_requires_one_available_producer():
    def fail(_invocation):
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
        _value_node("success", "available"),
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

    result = run_stage(
        "initialize",
        _compile(registrations, stage),
        _node_context(),
        {},
    )

    assert result.status is ExecutionStatus.INCONCLUSIVE
    assert result.outputs["collector"] == ("available",)

    all_failed = StageConfiguration.model_validate(
        {"nodes": {"failure": {}, "collector": {}}}
    )
    result = run_stage(
        "initialize",
        _compile(registrations, all_failed),
        _node_context(),
        {},
    )

    assert result.status is ExecutionStatus.ERROR
    assert "collector" not in result.outputs
    assert result.diagnostics[-1].message.endswith(
        "input 'values' requires at least one value"
    )


def test_union_output_must_be_safe_for_every_consumer_value():
    registrations = (
        NodeRegistration(
            "producer",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": str | int},
            lambda _invocation: NodeResult({"value": 1}),
        ),
        NodeRegistration(
            "consumer",
            "initialize",
            EmptyNodeConfiguration,
            {"value": str},
            {"value": str},
            lambda invocation: NodeResult({"value": invocation.inputs["value"]}),
        ),
    )
    stage = StageConfiguration.model_validate(
        {
            "nodes": {
                "producer": {},
                "consumer": {"inputs": {"value": "producer"}},
            }
        }
    )

    with pytest.raises(ValueError, match="is not compatible"):
        _compile(registrations, stage)


def test_failed_optional_input_does_not_skip_consumer():
    registrations = (
        NodeRegistration(
            "producer",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": str},
            lambda _invocation: NodeResult({}, status=ExecutionStatus.ERROR),
        ),
        NodeRegistration(
            "consumer",
            "initialize",
            EmptyNodeConfiguration,
            {"value": str | None},
            {"value": str},
            lambda invocation: NodeResult(
                {"value": invocation.inputs["value"] or "fallback"}
            ),
        ),
    )
    stage = StageConfiguration.model_validate(
        {
            "outputs": ["consumer"],
            "nodes": {
                "producer": {},
                "consumer": {"inputs": {"value": "producer"}},
            },
        }
    )
    result = run_stage(
        "initialize",
        _compile(registrations, stage),
        _node_context(),
        {},
    )

    assert result.outputs == {"consumer": "fallback"}


class _PrivateConfiguration(BaseModel):
    label: str

    model_config = ConfigDict(extra="forbid", frozen=True)


class _EntryPoint:
    name = "initialize.private_node"

    def __init__(self, loads: list[str]) -> None:
        self._loads = loads

    def load(self) -> NodeRegistration:
        self._loads.append("loaded")
        return NodeRegistration(
            "private_node",
            "initialize",
            _PrivateConfiguration,
            {},
            {"value": str},
            lambda invocation: NodeResult(
                {"value": invocation.configuration.label},
                diagnostics=(
                    ExecutionDiagnostic(
                        "private.warning",
                        "private diagnostic",
                        "warning",
                    ),
                ),
            ),
        )


class _SharedEntryPoint:
    def __init__(
        self,
        stage: Literal["initialize", "review"],
        loads: list[str],
    ) -> None:
        self.name = f"{stage}.shared"
        self._stage = stage
        self._loads = loads

    def load(self) -> NodeRegistration:
        self._loads.append(self._stage)
        return NodeRegistration(
            "shared",
            self._stage,
            EmptyNodeConfiguration,
            {},
            {"value": str},
            lambda _invocation: NodeResult({"value": self._stage}),
        )


@pytest.mark.parametrize(
    ("node_name", "entry_points"),
    (
        ("private_node", (_EntryPoint([]), _EntryPoint([]))),
        ("index", (type("IndexEntryPoint", (), {"name": "initialize.index"})(),)),
    ),
)
def test_private_node_registration_collisions_fail_before_loading(
    node_name: str,
    entry_points: tuple[object, ...],
) -> None:
    configuration = ExecutionConfiguration.model_validate(
        {"stages": {"initialize": {"nodes": {node_name: {}}}}}
    )

    with pytest.raises(ValueError, match="Multiple|conflicts with a built-in"):
        _service(configuration, entry_points=entry_points)


def test_only_configured_private_nodes_are_loaded_and_receive_configuration():
    loads: list[str] = []
    entry_point = _EntryPoint(loads)
    _service(entry_points=(entry_point,))
    assert loads == []

    configuration = ExecutionConfiguration.model_validate(
        {
            "stages": {
                "initialize": {
                    "outputs": ["private_node"],
                    "nodes": {"private_node": {}},
                },
            },
            "node_configuration": {
                "initialize": {"private_node": {"label": "private"}}
            },
        }
    )
    service, _calls = _service(configuration, entry_points=(entry_point,))

    diagnostic_callback = Mock()
    result = service.execute_graph(
        callbacks={"diagnostic_callback": diagnostic_callback}
    )

    assert loads == ["loaded"]
    assert result.outputs["initialize"]["private_node"] == "private"
    assert diagnostic_callback.call_args.args[0].code == "private.warning"


def test_private_node_names_are_scoped_by_stage():
    loads: list[str] = []
    catalog = NodeCatalog(
        (),
        (
            _SharedEntryPoint("initialize", loads),
            _SharedEntryPoint("review", loads),
        ),
    )

    assert catalog.resolve("initialize", "shared").stage == "initialize"
    assert catalog.resolve("review", "shared").stage == "review"
    assert loads == ["initialize", "review"]


def test_private_registration_must_match_selected_stage():
    loads: list[str] = []
    entry_point = _EntryPoint(loads)
    configuration = ExecutionConfiguration.model_validate(
        {
            "inputs": {"review_request": {"mode": "code"}},
            "stages": {
                "initialize": {
                    "outputs": {"codegraph": "codegraph.codegraph"},
                    "nodes": {"codegraph": {}},
                },
                "review": {
                    "inputs": {"codegraph": "initialize.codegraph"},
                    "nodes": {
                        "private_node": {},
                        "result": {
                            "inputs": {
                                "reviews": ["private_node"],
                                "codegraph": "$inputs.codegraph",
                            },
                            "formats": ["sarif"],
                        },
                    },
                },
            },
        }
    )

    with pytest.raises(ValueError, match="not registered for stage 'review'"):
        _service(configuration, entry_points=(entry_point,))
    assert loads == []


_PortUserId = NewType("_PortUserId", int)
_PortOtherId = NewType("_PortOtherId", int)
_PortStaffId = NewType("_PortStaffId", _PortUserId)


type _OptionalIntegerPort = int | None
type _OptionalCollectionPort = tuple[int, ...] | None


class _ExternalPortResource:
    pass


@dataclass
class _ExternalPortPayload:
    value: _ExternalPortResource


@pytest.mark.parametrize(
    ("source_annotation", "target_annotation", "value"),
    (
        (Literal[1, None], int | None, None),
        (_PortUserId, _PortUserId, _PortUserId(3)),
        (_PortUserId, int, _PortUserId(3)),
        (_PortStaffId, _PortUserId, _PortStaffId(_PortUserId(3))),
        (list[_PortUserId], list[_PortUserId], [_PortUserId(3)]),
        (list[_PortUserId], list[int], [_PortUserId(3)]),
        (_OptionalIntegerPort, int | None, None),
        (type(None), Literal[None], None),
        (dict[str, int], Mapping[str, int], {"value": 3}),
        (list[int], Sequence[int], [3]),
        (tuple[int, ...], Sequence[int], (1, 2)),
        (tuple[int, ...], tuple[int, ...], ()),
        (tuple[int, str], Sequence[object], (1, "two")),
        (tuple[int, str], tuple[object, ...], (1, "two")),
        (tuple[()], tuple[()], ()),
        (Tuple[()], tuple[()], ()),
        (tuple[()], Tuple[()], ()),
        (Tuple[()], Sequence[int], ()),
        (tuple, tuple, (1, "two")),
        (Tuple, tuple, (1, "two")),
        (tuple, Tuple, (1, "two")),
        (
            Annotated[_ExternalPortPayload, "external"],
            _ExternalPortPayload | None,
            _ExternalPortPayload(_ExternalPortResource()),
        ),
        (
            list[_ExternalPortPayload],
            Sequence[_ExternalPortPayload],
            [_ExternalPortPayload(_ExternalPortResource())],
        ),
    ),
)
def test_typed_node_ports_round_trip_without_coercion(
    source_annotation, target_annotation, value
):
    registrations = (
        NodeRegistration(
            "source",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": source_annotation},
            lambda _invocation: NodeResult({"value": value}),
        ),
        NodeRegistration(
            "consumer",
            "initialize",
            EmptyNodeConfiguration,
            {"value": target_annotation},
            {"value": target_annotation},
            lambda invocation: NodeResult(dict(invocation.inputs)),
        ),
    )
    stage = StageConfiguration.model_validate(
        {
            "nodes": {"source": {}, "consumer": {"inputs": {"value": "source.value"}}},
            "outputs": {"value": "consumer.value"},
        }
    )

    result = run_stage(
        "initialize", _compile(registrations, stage), _node_context(), {}
    )

    assert result.status is ExecutionStatus.OK
    assert result.outputs["value"] == value


@pytest.mark.parametrize("explicit", (False, True))
@pytest.mark.parametrize(
    "annotation,source_annotation,value",
    (
        (tuple[int, ...] | None, int, 3),
        (Annotated[tuple[int, ...] | None, "values"], int, 3),
        (tuple[int, ...] | Literal[None], int, 3),
        (_OptionalCollectionPort, int, 3),
        (tuple[None, ...], None, None),
        (tuple[type(None), ...], type(None), None),
        (tuple[None, ...] | None, type(None), None),
    ),
)
def test_homogeneous_tuple_collects_producer_values(
    annotation, source_annotation, value, explicit
):
    registrations = (
        NodeRegistration(
            "source",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": source_annotation},
            lambda _invocation: NodeResult({"value": value}),
        ),
        NodeRegistration(
            "consumer",
            "initialize",
            EmptyNodeConfiguration,
            {"value": annotation},
            {"value": annotation},
            lambda invocation: NodeResult(dict(invocation.inputs)),
        ),
    )
    stage = StageConfiguration.model_validate(
        {
            "nodes": {
                "source": {},
                "consumer": {"inputs": {"value": ["source.value"]}} if explicit else {},
            },
            "outputs": {"value": "consumer.value"},
        }
    )

    result = run_stage(
        "initialize", _compile(registrations, stage), _node_context(), {}
    )

    assert result.status is ExecutionStatus.OK
    assert result.outputs["value"] == (value,)


@pytest.mark.parametrize("annotation", (str, tuple[int, str], tuple[()]))
def test_even_empty_multiple_source_binding_requires_homogeneous_tuple(annotation):
    registration = NodeRegistration(
        "consumer",
        "initialize",
        EmptyNodeConfiguration,
        {"value": annotation},
        {},
        lambda _invocation: NodeResult({}),
    )
    stage = StageConfiguration.model_validate(
        {"nodes": {"consumer": {"inputs": {"value": []}}}}
    )

    with pytest.raises(ValueError, match="does not accept multiple sources"):
        _compile((registration,), stage)


@pytest.mark.parametrize(
    "annotation", (type(None), Literal[None], Annotated[int | None, "optional"])
)
@pytest.mark.parametrize("explicit", (False, True))
def test_absent_optional_stage_input_is_none_for_explicit_and_implicit_binding(
    annotation, explicit
):
    registration = NodeRegistration(
        "consumer",
        "initialize",
        EmptyNodeConfiguration,
        {"value": annotation},
        {"value": annotation},
        lambda invocation: NodeResult(dict(invocation.inputs)),
    )
    stage = StageConfiguration.model_validate(
        {
            "nodes": {
                "consumer": {"inputs": {"value": "$inputs.value"}} if explicit else {}
            }
        }
    )
    plan = compile_stage(
        NodeCatalog((registration,), ()), "initialize", stage, {}, {"value": annotation}
    )

    result = run_stage("initialize", plan, _node_context(), {})

    assert result.status is ExecutionStatus.OK
    assert result.outputs["consumer"] is None


@pytest.mark.parametrize(
    "annotation,value",
    (
        (int, "3"),
        (int | None, "3"),
        (Annotated[int | None, "strict"], "3"),
        (_PortUserId, "3"),
        (list[_PortUserId], ["3"]),
    ),
)
def test_node_port_rejects_string_instead_of_coercing_integer(annotation, value):
    handler = Mock(return_value=NodeResult({}))
    registration = NodeRegistration(
        "consumer",
        "initialize",
        EmptyNodeConfiguration,
        {"value": annotation},
        {},
        handler,
    )
    stage = StageConfiguration.model_validate({"nodes": {"consumer": {}}})
    plan = compile_stage(
        NodeCatalog((registration,), ()), "initialize", stage, {}, {"value": annotation}
    )

    result = run_stage("initialize", plan, _node_context(), {"value": value})

    assert result.status is ExecutionStatus.ERROR
    assert result.diagnostics[0].code == "execution.node_failed"
    handler.assert_not_called()


@pytest.mark.parametrize(
    "source_annotation,target_annotation,value",
    (
        (bool, int, True),
        (Literal[True], int, True),
        (Tuple, tuple[int, ...], ("wrong",)),
        (tuple[int, ...], Tuple[()], (1,)),
        (int, _PortUserId, 3),
        (_PortUserId, _PortOtherId, _PortUserId(3)),
        (list[int], list[_PortUserId], [3]),
        (list[_PortUserId], list[_PortOtherId], [_PortUserId(3)]),
    ),
)
def test_incompatible_port_annotations_reject_explicit_binding(
    source_annotation, target_annotation, value
):
    registrations = (
        NodeRegistration(
            "source",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {"value": source_annotation},
            lambda _invocation: NodeResult({"value": value}),
        ),
        NodeRegistration(
            "consumer",
            "initialize",
            EmptyNodeConfiguration,
            {"value": target_annotation},
            {},
            lambda _invocation: NodeResult({}),
        ),
    )
    stage = StageConfiguration.model_validate(
        {"nodes": {"source": {}, "consumer": {"inputs": {"value": "source.value"}}}}
    )

    with pytest.raises(ValueError, match="not compatible"):
        _compile(registrations, stage)


@pytest.mark.parametrize(
    "invalid_result",
    (
        {},
        NodeResult({}, "ok"),
        NodeResult(None),
        NodeResult({}, diagnostics=None),
        NodeResult({}, diagnostics=("bad",)),
        NodeResult({}, diagnostics=(ExecutionDiagnostic("bad", "bad", "invalid"),)),
        *(
            NodeResult(
                {}, status, (ExecutionDiagnostic("bad", "bad", UserString(severity)),)
            )
            for status in (ExecutionStatus.OK, ExecutionStatus.ERROR)
            for severity in ("warning", "error")
        ),
    ),
)
def test_invalid_node_result_is_contained_and_independent_output_survives(
    invalid_result,
):
    registrations = (
        NodeRegistration(
            "invalid",
            "initialize",
            EmptyNodeConfiguration,
            {},
            {},
            lambda _invocation: invalid_result,
        ),
        _value_node("independent", "kept"),
    )
    stage = StageConfiguration.model_validate(
        {"nodes": {"invalid": {}, "independent": {}}}
    )

    result = run_stage(
        "initialize", _compile(registrations, stage), _node_context(), {}
    )

    assert result.status is ExecutionStatus.ERROR
    assert result.outputs == {"independent": "kept"}
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "execution.node_failed"


def test_pre_cancelled_stage_does_not_execute_handler():
    handler = Mock(return_value=NodeResult({}))
    node = NodeRegistration(
        "cancelled", "initialize", EmptyNodeConfiguration, {}, {}, handler
    )
    stage = StageConfiguration.model_validate({"nodes": {"cancelled": {}}})
    context = _node_context()
    context = replace(
        context, runtime=replace(context.runtime, is_cancelled=lambda: True)
    )

    with pytest.raises(CancelledError):
        run_stage("initialize", _compile((node,), stage), context, {})

    handler.assert_not_called()


def test_node_cancelled_error_propagates_instead_of_becoming_failure_diagnostic():
    handler = Mock(side_effect=CancelledError("cancelled"))
    node = NodeRegistration(
        "cancelled", "initialize", EmptyNodeConfiguration, {}, {}, handler
    )
    stage = StageConfiguration.model_validate({"nodes": {"cancelled": {}}})

    with pytest.raises(CancelledError, match="cancelled"):
        run_stage("initialize", _compile((node,), stage), _node_context(), {})


def test_node_configuration_mutation_does_not_leak_into_next_invocation():
    class Configuration(BaseModel):
        values: list[int] = []

    seen = []

    def execute(invocation):
        seen.append(tuple(invocation.configuration.values))
        invocation.configuration.values.append(1)
        return NodeResult({})

    node = NodeRegistration("configured", "initialize", Configuration, {}, {}, execute)
    stage = StageConfiguration.model_validate({"nodes": {"configured": {}}})
    plan = _compile((node,), stage)

    for _ in range(2):
        assert (
            run_stage("initialize", plan, _node_context(), {}).status
            is ExecutionStatus.OK
        )

    assert seen == [(), ()]


@pytest.mark.parametrize(
    "annotation,value",
    (
        (_ExternalPortPayload, _ExternalPortPayload(_ExternalPortResource())),
        (_PortUserId, _PortUserId(3)),
    ),
)
def test_annotated_output_keeps_custom_validation(annotation, value):
    checked = []

    def validate(payload):
        checked.append(payload)
        return payload

    node = NodeRegistration(
        "payload",
        "initialize",
        EmptyNodeConfiguration,
        {},
        {"value": Annotated[annotation, AfterValidator(validate)]},
        lambda _invocation: NodeResult({"value": value}),
    )
    stage = StageConfiguration.model_validate({"nodes": {"payload": {}}})

    result = run_stage("initialize", _compile((node,), stage), _node_context(), {})

    assert result.status is ExecutionStatus.OK
    assert result.outputs["payload"] is value
    assert checked == [value]


@pytest.mark.parametrize("annotation", (123, list[123]))
def test_compiler_rejects_malformed_stage_input_annotation_even_for_any_consumer(
    annotation,
):
    node = NodeRegistration(
        "consumer",
        "initialize",
        EmptyNodeConfiguration,
        {"value": Any},
        {},
        lambda _invocation: NodeResult({}),
    )
    stage = StageConfiguration.model_validate({"nodes": {"consumer": {}}})

    with pytest.raises(TypeError, match="unsupported annotation"):
        compile_stage(
            NodeCatalog((node,), ()), "initialize", stage, {}, {"value": annotation}
        )


@pytest.mark.parametrize("configured", (False, True), ids=("defaults", "yaml-values"))
def test_configuration_snapshot_rebuilds_private_state_without_revalidating_normalized_values(
    configured,
):
    class NestedConfiguration(BaseModel):
        values: list[int] = Field(alias="items")
        _lock: object = PrivateAttr(default_factory=threading.Lock)

        @field_validator("values")
        @classmethod
        def increment(cls, values):
            return [value + 1 for value in values]

    class Configuration(BaseModel):
        nested: NestedConfiguration = Field(
            default_factory=lambda: NestedConfiguration(items=[2])
        )

    seen, locks = [], []

    def execute(invocation):
        configuration = invocation.configuration.nested
        locks.append(configuration._lock)
        with configuration._lock:
            seen.append(tuple(configuration.values))
            configuration.values.append(99)
        return NodeResult({})

    registration = NodeRegistration(
        "configured", "initialize", Configuration, {}, {}, execute
    )
    stage = StageConfiguration.model_validate({"nodes": {"configured": {}}})
    raw = {"nested": {"items": [2]}} if configured else {}
    plan = compile_stage(
        NodeCatalog((registration,), ()),
        "initialize",
        stage,
        {"configured": raw},
        {},
    )
    if configured:
        raw["nested"]["items"].append(500)

    for _ in range(2):
        assert (
            run_stage("initialize", plan, _node_context(), {}).status
            is ExecutionStatus.OK
        )

    assert seen == [(3,), (3,)]
    assert locks[0] is not locks[1]


@pytest.mark.parametrize("port", ("input", "output"))
@pytest.mark.parametrize("as_model", (False, True), ids=("mapping", "model"))
def test_concrete_model_ports_require_instances(port, as_model):
    class Payload(BaseModel):
        value: int

    value = Payload(value=1) if as_model else {"value": 1}
    handler = Mock(
        return_value=NodeResult({"value": value} if port == "output" else {})
    )
    registration = NodeRegistration(
        "model",
        "initialize",
        EmptyNodeConfiguration,
        {"value": Payload} if port == "input" else {},
        {"value": Payload} if port == "output" else {},
        handler,
    )
    stage = StageConfiguration.model_validate({"nodes": {"model": {}}})
    plan = compile_stage(
        NodeCatalog((registration,), ()),
        "initialize",
        stage,
        {},
        {"value": Payload} if port == "input" else {},
    )
    result = run_stage(
        "initialize", plan, _node_context(), {"value": value} if port == "input" else {}
    )

    assert result.status is (ExecutionStatus.OK if as_model else ExecutionStatus.ERROR)
    if port == "input" and not as_model:
        handler.assert_not_called()
    else:
        handler.assert_called_once()
    if not as_model:
        assert result.diagnostics[0].code == "execution.node_failed"
        assert "Input should be an instance of Payload" in result.diagnostics[0].message


@pytest.mark.parametrize(
    "boundary", ["handler", "progress", "diagnostic", "job_failure"]
)
def test_node_cancellation_is_checked_before_publishing_success(boundary):
    captured = []

    def execute(invocation):
        captured.append(invocation.context)
        if boundary == "handler":
            invocation.context.jobs.cancel()
        if boundary == "job_failure":

            def fail(_value):
                raise ValueError("ordinary job failure")

            invocation.context.jobs.run([1], fail, label=None, result_key=str)
        return NodeResult(
            {"value": "must not publish"},
            diagnostics=(ExecutionDiagnostic("note", "note", "warning"),),
        )

    def progress(event):
        if boundary == "progress" and event["event"] == "execution_node_end":
            captured[0].jobs.cancel()

    def diagnostic(_value):
        if boundary == "diagnostic":
            captured[0].jobs.cancel()

    node = NodeRegistration(
        "cancel", "initialize", EmptyNodeConfiguration, {}, {"value": str}, execute
    )
    stage = StageConfiguration.model_validate({"nodes": {"cancel": {}}})
    context = _node_context()
    scheduler = JobScheduler(1)
    context = replace(
        context,
        runtime=replace(context.runtime, jobs=scheduler.limit(1)),
        callbacks=NodeCallbacks(progress=progress, diagnostic=diagnostic),
    )
    try:
        if boundary == "job_failure":
            result = run_stage("initialize", _compile((node,), stage), context, {})
            assert result.status is ExecutionStatus.ERROR
            assert "ordinary job failure" in result.diagnostics[0].message
        else:
            with pytest.raises(CancelledError, match="node was cancelled"):
                run_stage("initialize", _compile((node,), stage), context, {})
        assert captured[0].runtime.is_cancelled()
    finally:
        scheduler.close()


def test_shared_stage_drain_retries_an_interrupted_wait_before_returning(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    from metis.engine.execution import runner

    started = threading.Event()
    release = threading.Event()
    retried = threading.Event()
    submit = runner.submit_with_current_context

    def observe_submit(executor, function, stage_name, node, *args):
        future = submit(executor, function, stage_name, node, *args)
        if node.name == "waiter":
            result = future.result
            interrupted = False

            def interrupt_wait(*args, **kwargs):
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    assert not future.done()
                    raise KeyboardInterrupt("interrupt while draining")
                retried.set()
                return result(*args, **kwargs)

            future.result = interrupt_wait
        return future

    def wait_for_release(_invocation):
        started.set()
        assert release.wait(5)
        return NodeResult({"value": "drained"})

    def interrupt(_invocation):
        assert started.wait(5)
        raise KeyboardInterrupt("initial stage interrupt")

    registrations = tuple(
        NodeRegistration(
            name, "initialize", EmptyNodeConfiguration, {}, {"value": str}, execute
        )
        for name, execute in (("waiter", wait_for_release), ("interrupt", interrupt))
    )
    stage = StageConfiguration.model_validate(
        {"nodes": {"waiter": {}, "interrupt": {}}}
    )
    monkeypatch.setattr(runner, "submit_with_current_context", observe_submit)
    with ThreadPoolExecutor(max_workers=2) as nodes:
        with ThreadPoolExecutor(max_workers=1) as caller:
            execution = caller.submit(
                run_stage,
                "initialize",
                _compile(registrations, stage),
                _node_context(),
                {},
                executor=nodes,
            )
            try:
                assert retried.wait(2), "An interrupted wait skipped the active node"
                assert not execution.done()
            finally:
                release.set()
            with pytest.raises(KeyboardInterrupt, match="initial stage interrupt"):
                execution.result(timeout=5)


@pytest.mark.parametrize("boundary", ["node", "stage"])
@pytest.mark.parametrize("status", [ExecutionStatus.OK, ExecutionStatus.INCONCLUSIVE])
def test_cancellation_during_output_logging_rejects_success(
    boundary, status, node_jobs, tmp_path
):
    from pydantic import model_serializer

    from metis import runlog

    caller = threading.current_thread()
    cancellation = threading.Event()
    captured = []

    class Payload(BaseModel):
        value: str

        @model_serializer
        def serialize(self):
            if threading.current_thread() is caller:
                if boundary == "stage":
                    cancellation.set()
            elif boundary == "node":
                captured[0].jobs.cancel()
            return {"value": self.value}

    def execute(invocation):
        captured.append(invocation.context)
        return NodeResult({"value": Payload(value="must not publish")}, status)

    node = NodeRegistration(
        "late", "initialize", EmptyNodeConfiguration, {}, {"value": Payload}, execute
    )
    stage = StageConfiguration.model_validate({"nodes": {"late": {}}})
    context = _node_context()
    context = replace(
        context,
        runtime=replace(
            context.runtime,
            jobs=node_jobs.with_cancellation(cancellation),
            is_cancelled=cancellation.is_set,
        ),
    )
    with runlog.open_runlog(runlog.RunLogConfig(path=tmp_path / "trace.ndjson")):
        with pytest.raises(CancelledError, match=f"Execution {boundary} was cancelled"):
            run_stage("initialize", _compile((node,), stage), context, {})
    assert captured[0].runtime.is_cancelled()


@pytest.mark.parametrize("stage_fails", [False, True])
def test_owned_stage_retries_shutdown_and_preserves_first_error(
    monkeypatch, node_jobs, stage_fails
):
    from concurrent.futures import ThreadPoolExecutor

    from metis.engine.execution import runner

    started = threading.Event()
    release = threading.Event()
    draining = threading.Event()
    initial = KeyboardInterrupt("initial stage interrupt")
    shutdown_error = KeyboardInterrupt("first shutdown interrupt")
    owned_executors = []
    captured = []
    shutdown_attempts = 0

    class InterruptedExecutor(ThreadPoolExecutor):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            owned_executors.append(self)

        def shutdown(self, *args, **kwargs):
            nonlocal shutdown_attempts
            shutdown_attempts += 1
            if shutdown_attempts == 1:
                raise shutdown_error
            if shutdown_attempts == 2:
                assert captured[0].runtime.is_cancelled()
                raise KeyboardInterrupt("second shutdown interrupt")
            return super().shutdown(*args, **kwargs)

    submit = runner.submit_with_current_context

    def observe_submit(executor, function, stage_name, node, *args):
        future = submit(executor, function, stage_name, node, *args)
        if stage_fails and node.name == "waiter":
            result = future.result

            def observe_drain(*args, **kwargs):
                draining.set()
                return result(*args, **kwargs)

            future.result = observe_drain
        return future

    def waiter(invocation):
        captured.append(invocation.context)
        started.set()
        if stage_fails:
            assert release.wait(5)
        return NodeResult({"value": "drained"})

    def interrupt(_invocation):
        assert started.wait(5)
        if stage_fails:
            raise initial
        return NodeResult({"value": "done"})

    registrations = tuple(
        NodeRegistration(
            name, "initialize", EmptyNodeConfiguration, {}, {"value": str}, execute
        )
        for name, execute in (("waiter", waiter), ("interrupt", interrupt))
    )
    stage = StageConfiguration.model_validate(
        {"nodes": {"waiter": {}, "interrupt": {}}}
    )
    context = _node_context()
    context = replace(
        context, runtime=replace(context.runtime, max_workers=2, jobs=node_jobs)
    )
    monkeypatch.setattr(runner, "ThreadPoolExecutor", InterruptedExecutor)
    monkeypatch.setattr(runner, "submit_with_current_context", observe_submit)
    with ThreadPoolExecutor(max_workers=1) as caller:
        execution = caller.submit(
            run_stage, "initialize", _compile(registrations, stage), context, {}
        )
        try:
            if stage_fails:
                assert draining.wait(2), "Owned cleanup skipped its active handler"
                assert not execution.done()
        finally:
            release.set()
        with pytest.raises(KeyboardInterrupt) as raised:
            execution.result(timeout=5)
    assert raised.value is (initial if stage_fails else shutdown_error)
    assert shutdown_attempts == 3
    assert captured[0].runtime.is_cancelled()
    assert not any(
        thread.is_alive() for pool in owned_executors for thread in pool._threads
    )
