# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

from metis.engine.graphs.schemas import TriageDecisionModel
from metis.engine.reachability.domain import FunctionNode
from metis.engine.reachability.graph import ReachabilityGraph
from metis.engine.reachability.options import ReachabilityReviewOptions
from metis.engine.reachability.triage import (
    ReachabilityTriageRequest,
    ReachabilityTriageRunner,
    _parse_triage_decision,
)
from metis.engine.triage_service import TriageService
from metis.sarif.triage import SarifFinding


class _FakePromptRunner:
    def __init__(self):
        self.request = None

    def invoke(self, request):
        self.request = request
        return TriageDecisionModel(
            status="valid",
            reason="caller reaches target with no guard",
            evidence=["src/main.c:5"],
            resolution_chain=["src/main.c::caller -> src/main.c::target"],
            unresolved_hops=[],
        )


class _FallbackPromptRunner:
    def __init__(self):
        self.requests = []

    def invoke(self, request):
        self.requests.append(request)
        if len(self.requests) == 1:
            return None
        return TriageDecisionModel(
            status="invalid",
            reason="structured fallback refuted the claim",
            evidence=["src/main.c:1"],
            resolution_chain=["finding -> caller"],
            unresolved_hops=[],
        )


def _graph() -> ReachabilityGraph:
    graph = ReachabilityGraph()
    graph.add_node(
        FunctionNode(
            "src/main.c::caller",
            "src/main.c",
            "caller",
            1,
            True,
            False,
            calls=["target"],
            source_reason="no internal callers",
        )
    )
    graph.add_node(
        FunctionNode(
            "src/main.c::target",
            "src/main.c",
            "target",
            5,
            False,
            False,
            calls=["sink"],
        )
    )
    graph.add_node(
        FunctionNode(
            "src/main.c::sink",
            "src/main.c",
            "sink",
            9,
            False,
            True,
            sink_type="memory_write",
            sink_reason="test sink",
        )
    )
    graph.resolve_all_calls()
    return graph


def test_reachability_triage_builds_focused_graph_context(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text(
        "void caller(void) {\n"
        "  target();\n"
        "}\n\n"
        "void target(void) {\n"
        "  sink();\n"
        "}\n\n"
        "void sink(void) {}\n",
        encoding="utf-8",
    )
    tool = object()
    runner = ReachabilityTriageRunner(
        Mock(),
        "model",
        None,
        str(tmp_path),
        options=ReachabilityReviewOptions(max_workers=1),
        model_tools=(tool,),
        max_tool_rounds=3,
    )
    fake_runner = _FakePromptRunner()
    runner._runner = fake_runner

    decision = runner.triage(
        ReachabilityTriageRequest(
            message="target reaches sink",
            file_path="src/main.c",
            line=6,
            rule_id="R1",
            snippet="sink();",
        ),
        _graph(),
    )

    assert decision["status"] == "valid"
    assert fake_runner.request.model_tools == (tool,)
    assert fake_runner.request.max_tool_rounds == 3
    context = fake_runner.request.variables["reachability_context"]
    assert "== TARGET FUNCTION ==" in context
    assert "src/main.c::target" in context
    assert "direct_callers: src/main.c::caller" in context
    assert "src/main.c::caller -> src/main.c::target" in context


def test_triage_service_routes_supported_files_to_reachability():
    reachability = Mock()
    reachability.supports_file.return_value = True
    reachability.triage_finding.return_value = {
        "status": "invalid",
        "reason": "wrapper validates the value",
        "evidence": ["src/main.c:4"],
        "resolution_chain": ["finding -> wrapper"],
        "unresolved_hops": [],
    }
    service = TriageService(
        codebase_path=".",
        llm_provider=Mock(),
        llama_query_model="model",
        chat_model_kwargs={"reasoning_effort": "high"},
        plugin_config={},
        max_workers=1,
        triage_checkpoint_every=50,
        triage_tool_timeout_seconds=12,
        get_plugin_for_path=lambda _path: None,
        get_language_name_for_path=lambda _path: "c",
        model_tools=("navigation",),
        model_tool_max_rounds=6,
        reachability_service=reachability,
        reachability_settings={"reasoning_effort": "high"},
    )
    service._get_thread_triage_graph = Mock(side_effect=AssertionError("generic path"))
    finding = SarifFinding(
        run_index=0,
        result_index=0,
        message="reported issue",
        rule_id="R1",
        file_path="src/main.c",
        line=10,
        snippet="target();",
        source_tool="tool",
        is_metis_source=False,
        explanation="",
    )

    decision = service._triage_one_finding(finding, debug_callback=None)

    assert decision["status"] == "invalid"
    reachability.triage_finding.assert_called_once()
    request = reachability.triage_finding.call_args.args[0]
    assert request.file_path == "src/main.c"
    assert request.message == "reported issue"
    assert reachability.triage_finding.call_args.kwargs["model_tools"] == (
        "navigation",
    )


def test_reachability_triage_parser_normalizes_common_payload_shapes():
    decision = _parse_triage_decision(
        {
            "verdict": "confirmed",
            "justification": "The issue is shown at src/main.c:5.",
            "citations": [{"file": "src/main.c", "line": 5}],
            "chain": "reported line -> target function",
            "ignored_extra": "ok",
        }
    )

    assert decision is not None
    assert decision.status == "valid"
    assert decision.evidence == ["src/main.c:5"]
    assert decision.resolution_chain == ["reported line -> target function"]


def test_reachability_triage_uses_structured_fallback_after_tool_parse_failure(
    tmp_path,
):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text("void target(void) {}\n", encoding="utf-8")
    runner = ReachabilityTriageRunner(
        Mock(),
        "model",
        None,
        str(tmp_path),
        options=ReachabilityReviewOptions(max_workers=1),
        model_tools=(object(),),
        max_tool_rounds=2,
    )
    fake_runner = _FallbackPromptRunner()
    runner._runner = fake_runner
    graph = ReachabilityGraph()
    graph.add_node(
        FunctionNode(
            "src/main.c::target",
            "src/main.c",
            "target",
            1,
            True,
            False,
        )
    )

    decision = runner.triage(
        ReachabilityTriageRequest(
            message="claim",
            file_path="src/main.c",
            line=1,
        ),
        graph,
    )

    assert decision["status"] == "invalid"
    assert len(fake_runner.requests) == 2
    assert fake_runner.requests[0].model_tools
    assert fake_runner.requests[1].model_tools == ()
