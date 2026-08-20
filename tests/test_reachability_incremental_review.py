# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda
from pytest import MonkeyPatch
from pytest import raises

from metis import runlog
from metis.cli.review_checkpoints import review_checkpoint_callbacks
from metis.engine.codegraph import CallSite
from metis.engine.codegraph import CodeExpression
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import ControlCondition
from metis.engine.codegraph import FunctionNode
from metis.engine.codegraph import ValueAssignment
from metis.engine.execution.contracts import NodeCallbacks
from metis.engine.llm_runner import JsonPromptRunner
from metis.engine.nodes.reachability import finding_admission
from metis.engine.nodes.reachability import incremental_review
from metis.engine.nodes.reachability.domain import VulnerabilityFinding
from metis.engine.nodes.reachability.incremental_review import IncrementalGraphReviewer
from metis.engine.nodes.reachability.options import ReachabilityReviewOptions
from metis.engine.nodes.reachability.state import FactAtom
from metis.engine.nodes.reachability.state import FunctionContract
from metis.engine.nodes.reachability.state import GuardedTransfer
from metis.engine.nodes.reachability.state import NormalExit
from metis.engine.nodes.reachability.state import ReturnSubject
from metis.engine.nodes.reachability.state import StateEffect
from metis.engine.nodes.reachability.state import TrackedObjectSubject
from metis.engine.stages.review.checkpoints import ReviewCheckpointSession
from metis.providers.base import ChatProvider


def _function(name: str, line: int, *, source: bool = False) -> FunctionNode:
    return FunctionNode(
        unique_name=f"graph.c::{name}",
        file_path="graph.c",
        name=name,
        line_number=line,
        end_line=line,
        is_source=source,
        source_reason="test source" if source else "",
    )


def _graph(*nodes: FunctionNode) -> CodeGraph:
    graph = CodeGraph()
    for node in nodes:
        graph.add_node(node)
    graph.resolve_all_calls()
    return graph


def _reviewer(tmp_path: Path) -> IncrementalGraphReviewer:
    provider = Mock()
    provider.count_tokens.side_effect = lambda text, model=None: len(text)
    plugin = Mock()
    plugin.get_prompts.return_value = {
        "security_review_file": "Review the file. [[REVIEW_SCHEMA_FIELDS]]",
        "security_review_checks": "Check memory safety.",
    }
    repository = Mock()
    repository.get_plugin_for_path.return_value = plugin
    config = SimpleNamespace(
        codebase_path=str(tmp_path),
        plugin_config={"general_prompts": {"security_review_report": "Report."}},
        custom_prompt_text=None,
        custom_guidance_precedence="",
        max_token_length=100_000,
        llama_query_model="test-model",
        chat_model_kwargs={},
    )
    return IncrementalGraphReviewer(config, repository, provider, None)


def test_review_runs_one_discovery_pass_with_deterministic_contracts(
    tmp_path: Path,
    node_jobs,
) -> None:
    (tmp_path / "graph.c").write_text(
        "void root(void) { sink(); }\nvoid sink(void) {}\n",
        encoding="utf-8",
    )
    call = CallSite(
        "sink",
        1,
        0,
        start_byte=18,
        end_byte=24,
        target_ids=("graph.c::sink",),
    )
    root = _function("root", 1, source=True)
    root.call_sites = [call]
    root.calls = ["sink"]
    sink = _function("sink", 2)
    sink.set_tag("control.noreturn", value="_Noreturn", reason="test fact")
    reviewer = _reviewer(tmp_path)
    seen_bodies: list[str] = []
    progress_events: list[dict[str, object]] = []

    def invoke(request: Any) -> object:
        assert "gpu_ready" in request.system_prompt
        assert "customterm" in request.system_prompt
        assert request.system_prompt.index("gpu_ready") > request.system_prompt.index(
            "CODEGRAPH_EVIDENCE is source-grounded"
        )
        body = request.variables["body_text"]
        assert isinstance(body, str)
        seen_bodies.append(body)
        evidence_text = body.partition("CODEGRAPH_EVIDENCE (untrusted JSON):\n")[2]
        evidence, _end = json.JSONDecoder().raw_decode(evidence_text)
        contract = evidence["direct_function_contracts"][0]
        assert evidence["function_ids"][contract["function"]] == "::sink"
        assert contract["normal_exit"] == {
            "line": 2,
            "origin": "observed",
            "status": "impossible",
        }
        parsed = request.parse({"reviews": []})
        assert parsed is not None
        return parsed

    reviewer._runner.invoke = Mock(side_effect=invoke)
    outcome = reviewer.review(
        _graph(root, sink),
        jobs=node_jobs,
        options=ReachabilityReviewOptions(
            domain_profiles=(" GPU ",),
            domain_hints=("CustomTerm",),
            progress_callback=progress_events.append,
        ),
    )

    assert len(seen_bodies) == 1
    assert "CONTRACT_MANIFEST" not in seen_bodies[0]
    assert "STATE_REVIEW_CASES" not in seen_bodies[0]
    assert outcome.stats.packet_count == 1
    assert {
        "event": "reachability_phase_progress",
        "phase": "contracts",
        "completed": 0,
        "total": 2,
    } in progress_events
    assert {
        "event": "reachability_phase_progress",
        "phase": "contracts",
        "completed": 2,
        "total": 2,
    } in progress_events
    assert {
        "event": "reachability_phase_progress",
        "phase": "packets",
        "completed": 0,
        "total": 1,
    } in progress_events
    assert {
        "event": "reachability_phase_progress",
        "phase": "evidence",
        "completed": 0,
        "total": 1,
    } in progress_events
    assert {
        "event": "reachability_phase_progress",
        "phase": "evidence",
        "completed": 1,
        "total": 1,
    } in progress_events
    assert {
        "event": "reachability_phase_progress",
        "phase": "packets",
        "completed": 1,
        "total": 1,
    } in progress_events


def test_reachability_review_resumes_validated_packets(tmp_path: Path, node_jobs):
    (tmp_path / "graph.c").write_text(
        "void root(void) {}\n",
        encoding="utf-8",
    )
    reviewer = _reviewer(tmp_path)
    reviewer._runner.invoke = Mock(
        side_effect=lambda request: request.parse({"reviews": []})
    )
    callbacks = review_checkpoint_callbacks(
        codebase_path=tmp_path,
        enabled=True,
    )
    node_callbacks = NodeCallbacks(
        checkpoint=callbacks["review_checkpoint_callback"],
        resume=callbacks["review_resume_callback"],
    )
    graph = _graph(_function("root", 1, source=True))

    first = reviewer.review(
        graph,
        jobs=node_jobs,
        options=ReachabilityReviewOptions(
            checkpoint_session=ReviewCheckpointSession(
                "reachability",
                node_callbacks,
            )
        ),
    )
    second = reviewer.review(
        graph,
        jobs=node_jobs,
        options=ReachabilityReviewOptions(
            checkpoint_session=ReviewCheckpointSession(
                "reachability",
                node_callbacks,
            )
        ),
    )

    assert first == second
    reviewer._runner.invoke.assert_called_once()


def test_default_review_prompt_has_no_domain_hints(tmp_path: Path) -> None:
    prompt = _reviewer(tmp_path)._system_prompt("graph.c", ReachabilityReviewOptions())

    assert "User-provided domain hints:" not in prompt


def test_reachability_checkpoint_key_includes_provider(tmp_path: Path) -> None:
    reviewer = _reviewer(tmp_path)

    class Provider(ChatProvider):
        def __init__(self) -> None:
            self.config = {"base_url": "https://first.example"}

        def get_chat_model(self, **_kwargs):
            return Mock()

    provider = Provider()
    reviewer._llm_provider = provider
    first = reviewer._cache_key(
        "system",
        "body",
        model="model",
        reasoning_effort=None,
        response_schema_json="{}",
    )

    provider.config["base_url"] = "https://second.example"

    assert first != reviewer._cache_key(
        "system",
        "body",
        model="model",
        reasoning_effort=None,
        response_schema_json="{}",
    )


def test_compact_packet_uses_tables_numbered_source_and_target_tags(
    tmp_path: Path,
) -> None:
    source_lines = [
        "void root(int a, int b) {",
        "  int x = a + b;",
        "  int y = a - b;",
        "}",
    ]
    source = "\n".join(source_lines) + "\n"
    (tmp_path / "graph.c").write_text(source, encoding="utf-8")
    expressions: list[CodeExpression] = []
    assignments: list[ValueAssignment] = []
    for line, text in ((2, "a + b"), (3, "a - b")):
        start = source.index(text)
        expression = CodeExpression(
            text,
            line,
            start,
            start + len(text),
            identifiers=("a", "b"),
        )
        expressions.append(expression)
        assignments.append(
            ValueAssignment(
                expression,
                expression,
                "=",
                line,
                start,
                source.index(";", start),
            )
        )
    root = _function("root", 1)
    root.end_line = len(source_lines)
    root.assignments = assignments
    root.calls = ["helper"]
    root.call_sites = [
        CallSite(
            "helper",
            2,
            0,
            start_byte=expressions[0].start_byte,
            end_byte=source.index(";", expressions[0].start_byte),
            target_ids=("helper.c::helper",),
        )
    ]
    helper_condition = ControlCondition(
        CodeExpression(
            "ready",
            1,
            6,
            11,
            identifiers=("ready",),
            direct_identifier="ready",
        ),
        True,
    )
    helper = FunctionNode(
        "helper.c::helper",
        "helper.c",
        "helper",
        1,
        end_line=1,
        calls=["stop"],
        call_sites=[
            CallSite(
                "stop",
                1,
                0,
                start_byte=1,
                end_byte=5,
                target_ids=("stop.c::stop",),
                conditions=(helper_condition,),
            )
        ],
    )
    stop = FunctionNode("stop.c::stop", "stop.c", "stop", 1, end_line=1)
    stop.set_tag("control.noreturn", value="_Noreturn", reason="test fact")
    reviewer = _reviewer(tmp_path)

    packets, failures = reviewer._build_packets(
        _graph(root, helper, stop),
        (root.unique_name, helper.unique_name, stop.unique_name),
        options=ReachabilityReviewOptions(),
        memory_service=None,
        selected_node_ids={root.unique_name},
        contracts={
            helper.unique_name: FunctionContract(
                helper.unique_name,
                normal_exit=NormalExit("impossible", "observed", 1),
            )
        },
    )

    assert not failures
    assert len(packets) == 1
    body_text = packets[0].body_text
    evidence_text = body_text.partition("CODEGRAPH_EVIDENCE (untrusted JSON):\n")[2]
    evidence, _end = json.JSONDecoder().raw_decode(evidence_text)
    assert evidence["expression_table"] == [
        {"cols": [10, 15], "ids": [0, 1], "line": 2},
        {"cols": [10, 15], "ids": [0, 1], "line": 3},
    ]
    assert evidence["atom_table"] == ["a", "b", "ready"]
    assignment_data = evidence["functions"][0]["assignments"]
    assert [item["target"] for item in assignment_data] == [0, 1]
    assert all(item["target"] == item["value"] for item in assignment_data)
    direct_function = evidence["direct_functions"][0]
    assert direct_function["file_path"] == "helper.c"
    assert "call_index" not in direct_function["calls"][0]
    foreign_condition = evidence["condition_table"][0]
    assert foreign_condition["file_path"] == "helper.c"
    assert direct_function["calls"][0]["conditions"] == [0]
    assert "file_path" not in foreign_condition["expression"]
    direct_contract = evidence["direct_function_contracts"][0]
    assert direct_contract["file_path"] == "helper.c"
    assert direct_contract["normal_exit"]["line"] == 1
    assert evidence["function_tags"]["2"]["control.noreturn"] == [
        "_Noreturn",
        "test fact",
    ]
    assert "expression_table maps integer expression references" in body_text
    assert "atom_table maps integer references" in body_text
    assert "expand each reference at its use site" in body_text
    snippet = body_text.partition("\nSNIPPET:\n")[2].rstrip("\n").splitlines()
    assert snippet == [
        f"{number}: {line}" for number, line in enumerate(source_lines, 1)
    ]


def test_oversized_source_line_only_fails_its_function(tmp_path: Path) -> None:
    reviewer = _reviewer(tmp_path)
    source = "void small(void) {}\n" + "x" * (reviewer._config.max_token_length + 1)
    (tmp_path / "graph.c").write_text(source, encoding="utf-8")
    small = _function("small", 1)
    oversized = _function("oversized", 2)

    packets, failures = reviewer._build_packets(
        _graph(small, oversized),
        (small.unique_name, oversized.unique_name),
        options=ReachabilityReviewOptions(),
        memory_service=None,
    )

    assert [[node.unique_name for node in packet.nodes] for packet in packets] == [
        [small.unique_name]
    ]
    assert {(failure.function_id, failure.kind) for failure in failures} == {
        (oversized.unique_name, "context_overflow")
    }


def test_source_chunk_runtime_error_propagates(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    (tmp_path / "graph.c").write_text("void root(void) {}\n", encoding="utf-8")
    reviewer = _reviewer(tmp_path)
    root = _function("root", 1)
    monkeypatch.setattr(
        incremental_review,
        "_build_file_grouped_node_chunks",
        Mock(side_effect=RuntimeError("token counter failed")),
    )

    with raises(RuntimeError, match="token counter failed"):
        reviewer._build_packets(
            _graph(root),
            (root.unique_name,),
            options=ReachabilityReviewOptions(),
            memory_service=None,
        )


def test_invalid_discovery_packet_splits_and_reviews_children(
    tmp_path: Path,
    node_jobs,
) -> None:
    (tmp_path / "graph.c").write_text(
        "void first(void) {}\nvoid second(void) {}\n",
        encoding="utf-8",
    )
    reviewer = _reviewer(tmp_path)
    calls = 0

    def respond(_messages: object) -> dict[str, object | None]:
        nonlocal calls
        calls += 1
        return {
            "raw": AIMessage(
                content="",
                response_metadata={"finish_reason": "length"},
            ),
            "parsed": None,
            "parsing_error": ValueError("truncated structured response"),
        }

    chat = RunnableLambda(lambda _messages: AIMessage(content=""))
    chat.with_structured_output = lambda *_args, **_kwargs: RunnableLambda(respond)
    reviewer._llm_provider.get_chat_model.return_value = chat
    reviewer._runner = JsonPromptRunner(
        reviewer._llm_provider,
        max_attempts=1,
        retry_backoff_seconds=0,
    )
    with runlog.open_runlog(
        runlog.RunLogConfig(path=tmp_path / "trace.ndjson")
    ) as session:
        outcome = reviewer.review(
            _graph(_function("first", 1), _function("second", 2)),
            jobs=node_jobs,
            options=ReachabilityReviewOptions(),
        )

    assert calls == 3
    assert outcome.failed_node_ids == ("graph.c::first", "graph.c::second")
    assert outcome.stats.packet_count == 3
    attempts = [
        json.loads(line)
        for line in session.ndjson_path.read_text(encoding="utf-8").splitlines()
        if '"record":"span.end"' in line and '"kind":"attempt"' in line
    ]
    assert len(attempts) == 3
    assert {attempt["status"] for attempt in attempts} == {"inconclusive"}
    assert {attempt["attributes"]["failure"] for attempt in attempts} == {
        "structured validation failed: truncated structured response"
    }


def test_indexed_null_condition_reaches_deterministic_admission(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    node_jobs,
) -> None:
    source = (
        "void *allocate(void);\nvoid root(void) { void *p = allocate(); consume(p); }\n"
    )
    (tmp_path / "graph.c").write_text(source, encoding="utf-8")
    allocator_id = "graph.c::allocate"
    result = CodeExpression(
        "p",
        2,
        39,
        40,
        identifiers=("p",),
        direct_identifier="p",
    )
    producer = CallSite(
        "allocate",
        2,
        0,
        start_byte=43,
        end_byte=53,
        target_ids=(allocator_id,),
        result=result,
    )
    sink_argument = replace(result, start_byte=63, end_byte=64)
    sink = CallSite(
        "consume",
        2,
        1,
        start_byte=55,
        end_byte=65,
        arguments=(sink_argument,),
    )
    root = _function("root", 2, source=True)
    root.call_sites = [producer, sink]
    root.calls = ["allocate", "consume"]
    allocator = _function("allocate", 1)
    graph = _graph(root, allocator)
    contract = FunctionContract(
        allocator_id,
        normal_return_transfers=(
            GuardedTransfer(
                effects=(
                    StateEffect(
                        "negate",
                        FactAtom(ReturnSubject(allocator_id), "null"),
                        "observed",
                        1,
                    ),
                )
            ),
        ),
    )
    monkeypatch.setattr(
        incremental_review,
        "augment_function_contracts",
        lambda _graph, **_kwargs: {allocator_id: contract},
    )
    reviewer = _reviewer(tmp_path)

    def invoke(request: Any) -> object:
        body = request.variables["body_text"]
        evidence_text = body.partition("CODEGRAPH_EVIDENCE (untrusted JSON):\n")[2]
        evidence, _end = json.JSONDecoder().raw_decode(evidence_text)
        assert "call_results" not in evidence
        allocator_index = evidence["function_ids"].index("::allocate")
        contract_data = evidence["direct_function_contracts"][0]
        assert contract_data["function"] == allocator_index
        effect = contract_data["normal_returns"][0]["effects"][0]
        assert (effect["operation"], effect["atom"]["subject"]) == (
            "negate",
            {"function_id": allocator_index, "kind": "return"},
        )
        root_index = evidence["function_ids"].index("::root")
        root_data = next(
            item for item in evidence["functions"] if item["function_id"] == root_index
        )
        producer_data = root_data["calls"][0]
        assert [call["call_index"] for call in root_data["calls"]] == [0, 1]
        assert evidence["call_symbols"][producer_data["symbol"]] == "allocate"
        assert producer_data["result"]["result_index"] == 0
        parsed = request.parse(
            {
                "reviews": [
                    {
                        "issue": "Unchecked allocation",
                        "code_snippet": "consume(p);",
                        "start_line": 2,
                        "end_line": 2,
                        "reasoning": "The sink requires the allocation result to be null.",
                        "mitigation": "Check the result.",
                        "confidence": 0.9,
                        "cwe": "CWE-476",
                        "severity": "HIGH",
                        "necessary_condition_alternatives": [
                            {
                                "sink_call_index": 1,
                                "all_of": [{"call_result_index": 0}],
                            }
                        ],
                    }
                ]
            }
        )
        assert parsed is not None
        return parsed

    reviewer._runner.invoke = Mock(side_effect=invoke)
    outcome = reviewer.review(
        graph,
        jobs=node_jobs,
        options=ReachabilityReviewOptions(),
    )

    assert outcome.findings == ()
    assert outcome.stats.contradicted_finding_count == 1


def test_admission_uses_only_immediate_deterministic_nonnull_proofs() -> None:
    allocator_id = "graph.c::allocate"
    results = (
        CodeExpression("p", 1, 10, 11, identifiers=("p",), direct_identifier="p"),
        CodeExpression("q", 1, 30, 31, identifiers=("q",), direct_identifier="q"),
    )
    producers = (
        CallSite(
            "allocate",
            1,
            0,
            start_byte=1,
            end_byte=9,
            target_ids=(allocator_id,),
            result=results[0],
        ),
        CallSite(
            "allocate",
            1,
            0,
            start_byte=21,
            end_byte=29,
            target_ids=(allocator_id,),
            result=results[1],
        ),
    )
    sinks = (
        CallSite("consume", 1, 1, start_byte=12, end_byte=20, arguments=(results[0],)),
        CallSite("consume", 1, 1, start_byte=32, end_byte=40, arguments=(results[1],)),
    )
    root = _function("root", 1, source=True)
    root.call_sites = [producers[0], sinks[0], producers[1], sinks[1]]
    graph = _graph(root)
    finding = VulnerabilityFinding(
        id="finding",
        vulnerability_type="null dereference",
        severity="high",
        confidence=0.9,
        source_function=root.unique_name,
        source_file="graph.c",
        source_line=1,
        sink_function=root.unique_name,
        sink_file="graph.c",
        sink_line=1,
        primary_anchor={"start_line": 1, "end_line": 1},
    )
    conditions = tuple(
        finding_admission._GroundedNecessaryCondition(
            TrackedObjectSubject(
                root.unique_name,
                "graph.c",
                result.start_byte,
                result.end_byte,
            ),
        )
        for result in results
    )
    alternatives = tuple(
        finding_admission._GroundedNecessaryAlternative(index, (condition,))
        for index, condition in zip((1, 3), conditions, strict=True)
    )
    contract = FunctionContract(
        allocator_id,
        normal_return_transfers=(
            GuardedTransfer(
                effects=(
                    StateEffect(
                        "negate",
                        FactAtom(ReturnSubject(allocator_id), "null"),
                        "derived",
                        1,
                    ),
                )
            ),
        ),
    )

    def admission(
        selected_contract: FunctionContract = contract,
        selected_alternatives: tuple[
            finding_admission._GroundedNecessaryAlternative, ...
        ] = alternatives,
    ) -> tuple[frozenset[str], int]:
        return finding_admission._admitted_finding_ids(
            graph,
            {finding.id: finding},
            {finding.id: selected_alternatives},
            {allocator_id: selected_contract},
        )

    assert admission() == (frozenset(), 1)
    assert admission(selected_alternatives=()) == (frozenset((finding.id,)), 0)
    hypothesis = replace(
        contract,
        normal_return_transfers=(
            GuardedTransfer(
                effects=(
                    replace(
                        contract.normal_return_transfers[0].effects[0],
                        origin="hypothesis",
                    ),
                )
            ),
        ),
    )
    assert admission(hypothesis) == (frozenset((finding.id,)), 0)

    root.call_sites.insert(1, CallSite("may_alias", 1, 0, start_byte=10, end_byte=12))
    shifted = (
        replace(alternatives[0], sink_call_index=2),
        replace(alternatives[1], sink_call_index=4),
    )
    assert admission(selected_alternatives=shifted) == (
        frozenset((finding.id,)),
        0,
    )
