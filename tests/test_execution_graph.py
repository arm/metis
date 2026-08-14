# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import replace
from typing import Any
from typing import Literal
from unittest.mock import Mock

import pytest
from pydantic import BaseModel
from pydantic import ConfigDict

from metis.configuration import load_execution_config
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphReference
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
from metis.execution_nodes import EXECUTION_NODE_API_VERSION
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


def _configuration() -> ExecutionConfiguration:
    return ExecutionConfiguration.model_validate(
        {
            "inputs": {
                "review_request": {"mode": "code"},
            },
            "stages": {
                "initialize": {
                    "outputs": ["threat_model"],
                    "nodes": {
                        "threat_model": {"capabilities": ["memory"]},
                    },
                },
                "review": {
                    "depends_on": ["initialize"],
                    "nodes": {
                        "codegraph": {},
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
                        "codegraph": "review.codegraph",
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
        runtime=NodeRuntime("test", 2, 1000, {}, 1, lambda _text: 1),
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
        runtime=NodeRuntime("test", 1, 10, {}, 1, lambda _text: 100),
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
        runtime=NodeRuntime("test", 1, 1000, {}, 1, lambda _text: 1),
        callbacks=NodeCallbacks(),
    )


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
    review_run: ReviewRun | None = None,
    review_commands: list[ReviewCommand] | None = None,
    triage_options: TriageOptions | None = None,
    triage_runs: list[TriageRun] | None = None,
) -> tuple[ExecutionGraphService, list[object]]:
    calls: list[object] = []
    engine_config = Mock(
        codebase_path=".",
        llm_provider=Mock(count_tokens=lambda _text: 1),
        llama_query_model="test",
        max_workers=2,
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
            threat_model_node.create_node(engine_config, Mock()),
            index_node.registration,
            codegraph_node.registration,
            review_node.create_node(review),
            reachability_review_node.create_node(review),
            finding_dedup_node,
            review_results_node.registration,
            triage_node.create_node(triage_classifier),
            triage_results_node.registration,
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


def test_default_graph_runs_fixed_stages_and_passes_review_sarif(monkeypatch):
    configuration = ExecutionConfiguration.model_validate(load_execution_config())
    service, calls = _service(configuration)
    monkeypatch.setattr(
        "metis.engine.nodes.threat_model.registration.initialize_threat_model_memory",
        lambda *_args: {
            "status": "ok",
            "records_written": 0,
            "records_deleted": 0,
            "authoritative_sources": [],
        },
    )

    result = service.execute_graph()

    assert result.status is ExecutionStatus.OK
    assert calls == ["codegraph", "review", "review", "triage"]
    assert tuple(result.outputs) == ("initialize", "review", "triage")
    assert result.outputs["triage"]["sarif"] == result.outputs["review"]["sarif"]


def test_codegraph_node_seeds_file_review_from_target():
    codegraphs = Mock()
    reference = CodeGraphReference(
        revision=1,
        fingerprint="fingerprint",
        producer_version="test",
    )
    codegraphs.materialize.return_value = reference
    context = replace(
        _node_context(),
        stage="review",
        codegraphs=codegraphs,
    )

    result = codegraph_node.registration.execute(
        NodeInvocation(
            EmptyNodeConfiguration(),
            {"request": ReviewCommand(mode="file", target="src/target.c")},
            context,
        )
    )

    assert result.outputs == {"codegraph": reference}
    codegraphs.materialize.assert_called_once_with(
        seed_file="src/target.c",
        progress_callback=None,
    )


def test_inconclusive_review_still_feeds_triage(monkeypatch):
    service, calls = _service(
        review_run=_review_run(ReviewStatus.INCONCLUSIVE),
    )
    monkeypatch.setattr(
        "metis.engine.nodes.threat_model.registration.initialize_threat_model_memory",
        lambda *_args: {
            "status": "ok",
            "records_written": 0,
            "records_deleted": 0,
            "authoritative_sources": [],
        },
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


def test_failed_review_stops_before_triage(monkeypatch):
    service, calls = _service(
        review_run=ReviewRun(ReviewStatus.FAILED, None),
    )
    monkeypatch.setattr(
        "metis.engine.nodes.threat_model.registration.initialize_threat_model_memory",
        lambda *_args: {
            "status": "ok",
            "records_written": 0,
            "records_deleted": 0,
            "authoritative_sources": [],
        },
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

    def fail(_invocation):
        raise RuntimeError("failed")

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
        _value_node("independent", "ran"),
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

    context = replace(
        _node_context(),
        callbacks=NodeCallbacks(progress=events.append),
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
    assert [event["event"] for event in events] == [
        "execution_stage_start",
        "execution_node_start",
        "execution_node_end",
        "execution_node_start",
        "execution_node_end",
        "execution_node_skipped",
        "execution_stage_end",
    ]
    assert events[2]["status"] == "error"
    assert events[4]["status"] == "ok"
    assert events[5] == {
        "event": "execution_node_skipped",
        "stage": "initialize",
        "node": "dependant",
        "reason": "dependency_failed",
    }
    assert events[6]["status"] == "error"
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
            api_version=EXECUTION_NODE_API_VERSION,
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
            api_version=EXECUTION_NODE_API_VERSION,
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
                "review": {
                    "nodes": {
                        "codegraph": {},
                        "private_node": {},
                        "result": {
                            "inputs": {
                                "reviews": ["private_node"],
                                "codegraph": "codegraph",
                            },
                            "formats": ["sarif"],
                        },
                    }
                }
            },
        }
    )

    with pytest.raises(ValueError, match="not registered for stage 'review'"):
        _service(configuration, entry_points=(entry_point,))
    assert loads == []
