# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import FunctionNode
from metis.engine.capabilities.catalog import get_capability_manifest
from metis.engine.stages.triage.models import TriageDecisionModel
from metis.engine.nodes.reachability.options import ReachabilityReviewOptions
from metis.engine.nodes.reachability_triage.service import (
    ReachabilityTriageRequest,
    ReachabilityTriageRunner,
    ReachabilityTriageService,
    _parse_triage_decision,
    _target_node_for_finding,
)
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


def _graph() -> CodeGraph:
    graph = CodeGraph()
    graph.add_node(
        FunctionNode(
            "src/main.c::caller",
            "src/main.c",
            "caller",
            1,
            end_line=3,
            is_source=True,
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
            end_line=7,
            calls=["sink"],
        )
    )
    graph.add_node(
        FunctionNode(
            "src/main.c::sink",
            "src/main.c",
            "sink",
            9,
            end_line=9,
            is_sink=True,
            sink_type="memory_write",
            sink_reason="test sink",
        )
    )
    graph.resolve_all_calls()
    return graph


def _triage_service(reachability: Mock) -> ReachabilityTriageService:
    navigation_manifest = get_capability_manifest("navigation")
    assert navigation_manifest is not None
    return ReachabilityTriageService(
        reachability_service=reachability,
        settings={"reasoning_effort": "high"},
        max_workers=1,
        llm_provider=Mock(),
        model="model",
        usage_runtime=None,
        codebase_path=".",
        chat_model_kwargs={"reasoning_effort": "high"},
        normalize_path=lambda path: path.removeprefix("/project/"),
        model_tool_max_contract_chars=6000,
        navigation_manifest=navigation_manifest,
    )


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


def test_reachability_triage_does_not_assign_between_function_finding():
    graph = _graph()

    assert _target_node_for_finding(graph, "src/main.c", 4) is None


def test_reachability_triage_classifier_handles_supported_files():
    reachability = Mock()
    reachability.supports_file.return_value = True
    reachability.analysis_graph.return_value = CodeGraph()
    service = _triage_service(reachability)
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

    decision = service.classifier(CodeGraph())(finding, [], None)

    assert decision["status"] == "inconclusive"
    assert decision["missing_evidence"] == ["reachability_context"]


def test_reachability_triage_classifier_leaves_unsupported_files():
    reachability = Mock()
    reachability.supports_file.return_value = True
    service = _triage_service(reachability)
    reachability.analysis_graph.return_value = CodeGraph()
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

    decision = service.classifier(
        CodeGraph(),
        unavailable_files=("src/main.c",),
    )(finding, [], None)

    assert decision is None


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
    graph = CodeGraph()
    graph.add_node(
        FunctionNode(
            "src/main.c::target",
            "src/main.c",
            "target",
            1,
            is_source=True,
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
