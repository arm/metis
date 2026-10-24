# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import CancelledError
from concurrent.futures import ThreadPoolExecutor
import json
from threading import Barrier
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage

from metis.engine.capabilities.navigation import NavigationCapability
from metis.engine.concurrency import _bind_cancellation
from metis.engine.model_tool_runner import ModelInputLimitError
from metis.engine.nodes.triage.workflow import TriageWorkflow
from metis.engine.nodes.triage.workflow import triage_node_llm
from metis.engine.nodes.triage.workflow.llm import _build_user_prompt
from metis.engine.stages.triage.models import TriageDecisionModel
from metis.runlog import RunLogConfig
from metis.runlog import RunLogSession


class _FakeTool:
    name = "sed"
    description = "Read line window."
    metadata = {"metis_contract": "Navigation contract", "metis_contract_max_chars": 80}

    def __init__(self):
        self.calls = []

    def invoke(self, args):
        self.calls.append(args)
        return "10: value = request.args['x']"


class _FakeToolChat:
    def __init__(self):
        self.messages = []

    def invoke(self, messages):
        self.messages.append(list(messages))
        if len(self.messages) == 1:
            return AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "call-1",
                        "name": "sed",
                        "args": {
                            "path": "a.py",
                            "start_line": 8,
                            "end_line": 12,
                        },
                    }
                ],
            )
        return AIMessage(
            content=(
                '{"status":"valid","reason":"reported input reaches the cited line",'
                '"evidence":["a.py:10"],'
                '"resolution_chain":["reported finding -> a.py:10"],'
                '"unresolved_hops":[]}'
            )
        )


class _FakeChat:
    def __init__(self):
        self.bound_tools = None
        self.bound_chat = _FakeToolChat()

    def bind_tools(self, tools):
        self.bound_tools = list(tools)
        return self.bound_chat


class _FakeProvider:
    def __init__(self):
        self.chat = _FakeChat()

    def get_chat_model(self, **_kwargs):
        return self.chat


@pytest.fixture
def source_workflow(tmp_path):
    (tmp_path / "a.c").write_text(
        "int read(int *a, int i) {\n    return a[i];\n}\n", encoding="utf-8"
    )
    navigation = NavigationCapability(
        codebase_path=str(tmp_path), timeout_seconds=8, max_chars=16000
    )
    return TriageWorkflow(
        llm_provider=object(),
        llama_query_model="dummy",
        toolbox=navigation,
        plugin_config={},
    )


@pytest.fixture
def triage_request():
    return {
        "finding_message": "The index is not checked before access.",
        "finding_file_path": "a.c",
        "finding_line": 2,
        "finding_rule_id": "R1",
        "finding_snippet": "return a[i];",
    }


def test_triage_schema_allows_inconclusive_with_unresolved_hops():
    decision = TriageDecisionModel(
        status="inconclusive",
        reason="wrapper chain unresolved",
        evidence=[],
        resolution_chain=["reported finding -> PROJECT_STACK_ALLOC(...)"],
        unresolved_hops=["PROJECT_STACK_ALLOC macro expansion unknown"],
    )
    assert decision.status == "inconclusive"


@pytest.mark.parametrize("missing_decision", [False, True])
@pytest.mark.parametrize("decision_factory", [TriageDecisionModel, SimpleNamespace])
def test_triage_node_keeps_legacy_json_state(missing_decision, decision_factory):
    decision = decision_factory(
        status="invalid",
        reason="Guarded access",
        evidence=["a.c:2"],
        resolution_chain=["guard -> access"],
    )
    state = {"finding_message": "Reported issue"}
    result = triage_node_llm(
        state, invoke_decision=lambda *_args: None if missing_decision else decision
    )
    assert json.loads(json.dumps(result)) == {
        "finding_message": "Reported issue",
        "decision_status": "inconclusive" if missing_decision else "invalid",
        "decision_reason": (
            "Inconclusive because the triage model did not return a valid decision payload."
            if missing_decision
            else "Guarded access"
        ),
        "decision_evidence": [] if missing_decision else ["a.c:2"],
        "decision_resolution_chain": [] if missing_decision else ["guard -> access"],
        "decision_unresolved_hops": ["TRIAGE_DECISION_PARSE_FAILED"]
        if missing_decision
        else [],
        "triage_model_status": None if missing_decision else "invalid",
    }
    assert state == {"finding_message": "Reported issue"}


def test_triage_schema_rejects_inconclusive_without_unresolved_hops():
    with pytest.raises(ValueError):
        TriageDecisionModel(
            status="inconclusive",
            reason="uncertain",
            evidence=[],
            resolution_chain=["source -> sink"],
            unresolved_hops=[],
        )


def test_triage_user_prompt_includes_language_navigation_guidance():
    prompt = _build_user_prompt(
        {
            "finding_message": "unsafe call",
            "finding_file_path": "a.py",
            "finding_line": 10,
            "finding_rule_id": "AI001",
            "finding_snippet": "danger(x)",
            "triage_language": "python",
            "triage_language_guidance": "Inspect decorators and validators first.",
            "threat_model_context": [
                {
                    "summary": "Callers validate input.",
                    "metadata": {
                        "authority": "authoritative",
                        "scope_clauses": [],
                    },
                }
            ],
        }
    )

    assert "Language Context:" in prompt
    assert "- language: python" in prompt
    assert "Inspect decorators and validators first." in prompt
    assert "Threat-Model Context:" in prompt
    assert "Callers validate input." in prompt


@pytest.mark.parametrize(
    ("status", "reason", "unresolved_hops"),
    [
        (
            "valid",
            "The index is not validated before use. This is not a false positive.",
            ["FLOW_SINK_NOT_FOUND", "MACRO_DEFINITION_UNRESOLVED:PROJECT_STACK_ALLOC"],
        ),
        ("invalid", "Unknown inputs are rejected by the caller.", []),
        ("inconclusive", "I cannot determine the input contract.", ["caller missing"]),
    ],
)
def test_triage_preserves_structured_verdict_regardless_of_prose(
    source_workflow,
    triage_request,
    monkeypatch,
    tmp_path,
    status,
    reason,
    unresolved_hops,
):
    invoke = Mock(
        return_value=TriageDecisionModel(
            status=status,
            reason=reason,
            evidence=["a.c:2"],
            resolution_chain=["input -> a.c:2"],
            unresolved_hops=unresolved_hops,
        )
    )
    monkeypatch.setattr(source_workflow, "_invoke_triage_model", invoke)

    with RunLogSession(RunLogConfig(path=tmp_path / "triage.ndjson")) as session:
        result = source_workflow.triage(triage_request)

    invoke.assert_called_once()
    assert result["status"] == status
    assert result["reason"] == reason
    assert result["unresolved_hops"] == unresolved_hops
    assert result["decision_source"] == "model"
    assert result["validation_errors"] == []
    records = [
        json.loads(line) for line in session.ndjson_path.read_text().splitlines()
    ]
    assert [
        record["name"]
        for record in records
        if record["record"] == "span.start" and record["kind"] == "step"
    ] == ["triage.collect_evidence", "triage.triage"]
    final_state = next(
        record["attributes"]["final_state"]
        for record in records
        if record["record"] == "span.end" and record["kind"] == "workflow"
    )
    assert final_state["decision_status"] == result["status"]
    assert final_state["decision_evidence"] == result["evidence"]


@pytest.mark.parametrize(
    "template", ["{triage_input}", "{triage_input}\n{tool_outputs}"]
)
def test_custom_template_cannot_omit_evidence_used_to_validate_citations(
    source_workflow, triage_request, monkeypatch, template
):
    source_workflow.triage_decision_prompt = template
    triage_request["finding_snippet"] = "literal {tool_outputs} and {triage_input}"

    def decide(_system, prompt, **_kwargs):
        assert "literal {tool_outputs} and {triage_input}" in prompt
        assert prompt.count("2:     return a[i];") == 1
        return TriageDecisionModel(
            status="valid",
            reason="Source shows the access.",
            evidence=["a.c:2"],
            resolution_chain=["input -> array access"],
        )

    monkeypatch.setattr(source_workflow, "_invoke_triage_model", decide)

    assert source_workflow.triage(triage_request)["status"] == "valid"


def test_triage_checks_configured_input_budget_before_model_invocation(
    source_workflow, triage_request
):
    provider = Mock()
    provider.count_tokens.side_effect = lambda text, **_kwargs: len(text)
    source_workflow._prompt_runner._llm_provider = provider
    source_workflow.max_input_tokens = 1

    with pytest.raises(ModelInputLimitError):
        source_workflow.triage(triage_request)

    provider.get_chat_model.return_value.invoke.assert_not_called()


def test_triage_honors_cancellation_between_steps(
    source_workflow, triage_request, monkeypatch
):
    cancellation = Event()
    invoke = Mock()
    monkeypatch.setattr(source_workflow, "_invoke_triage_model", invoke)

    def cancel_after_collection(event):
        if event["event"] == "evidence_collection":
            cancellation.set()

    triage_request["debug_callback"] = cancel_after_collection
    with _bind_cancellation(cancellation.is_set), pytest.raises(CancelledError):
        source_workflow.triage(triage_request)

    invoke.assert_not_called()


def test_concurrent_findings_cannot_borrow_each_others_source(
    source_workflow, triage_request, tmp_path, monkeypatch
):
    (tmp_path / "b.c").write_text("void second(void) {}\n", encoding="utf-8")
    barrier = Barrier(2)

    def decide(_system, _prompt, **_kwargs):
        barrier.wait(timeout=5)
        return TriageDecisionModel(
            status="invalid",
            reason="The inspected operation is safe.",
            evidence=["b.c:1"],
            resolution_chain=["finding -> b.c:1"],
        )

    monkeypatch.setattr(source_workflow, "_invoke_triage_model", decide)
    requests = [
        triage_request,
        {**triage_request, "finding_file_path": "b.c", "finding_line": 1},
    ]
    with ThreadPoolExecutor(max_workers=2) as executor:
        first, second = executor.map(source_workflow.triage, requests)

    assert first["status"] == "inconclusive"
    assert first["validation_errors"] == ["UNOBSERVED_CITATION:b.c:1"]
    assert second["status"] == "invalid"
    assert second["validation_errors"] == []


@pytest.mark.parametrize("status", ["valid", "invalid"])
def test_triage_retains_findings_when_citations_are_unusable(
    source_workflow, triage_request, monkeypatch, status
):
    monkeypatch.setattr(
        source_workflow,
        "_invoke_triage_model",
        Mock(
            return_value=TriageDecisionModel(
                status=status,
                reason="The source proves the verdict.",
                evidence=["unseen.c:1"],
                resolution_chain=["input -> access"],
            )
        ),
    )

    result = source_workflow.triage(triage_request)

    assert result["status"] == "inconclusive"
    assert result["decision_source"] == "validation_failure"
    assert result["validation_errors"] == ["UNOBSERVED_CITATION:unseen.c:1"]
    assert result["unresolved_hops"]


def test_triage_requires_citations_for_builtin_invalid_decisions(
    source_workflow, triage_request, monkeypatch
):
    monkeypatch.setattr(
        source_workflow,
        "_invoke_triage_model",
        Mock(return_value=TriageDecisionModel(status="invalid", reason="Looks safe.")),
    )

    result = source_workflow.triage(triage_request)

    assert result["status"] == "inconclusive"
    assert result["decision_source"] == "validation_failure"
    assert "MISSING_EVIDENCE" in result["validation_errors"]
    assert "MISSING_RESOLUTION_CHAIN" in result["validation_errors"]


def test_triage_does_not_treat_reported_snippet_as_observed_source(
    source_workflow, triage_request, monkeypatch
):
    monkeypatch.setattr(
        source_workflow.toolbox,
        "sed",
        Mock(side_effect=OSError("source unavailable")),
    )
    invoke = Mock(
        return_value=TriageDecisionModel(
            status="invalid",
            reason="The reported snippet appears safe.",
            evidence=["a.c:2"],
            resolution_chain=["reported snippet -> a.c:2"],
        )
    )
    monkeypatch.setattr(source_workflow, "_invoke_triage_model", invoke)

    result = source_workflow.triage(triage_request)

    invoke.assert_called_once()
    assert result["status"] == "inconclusive"
    assert result["decision_source"] == "validation_failure"
    assert result["validation_errors"] == ["UNOBSERVED_CITATION:a.c:2"]


@pytest.mark.parametrize(
    ("errors", "source"),
    [
        ([], "execution_failure"),
        (["UNOBSERVED_CITATION:unseen.c:1"], "validation_failure"),
    ],
)
def test_triage_distinguishes_parse_failure_from_citation_failure(
    source_workflow, triage_request, monkeypatch, errors, source
):
    def no_decision(_system, _prompt, *, source_evidence):
        source_evidence.errors = errors
        return None

    monkeypatch.setattr(source_workflow, "_invoke_triage_model", no_decision)

    result = source_workflow.triage(triage_request)

    assert result["status"] == "inconclusive"
    assert result["decision_source"] == source
    assert result["validation_errors"] == (errors or ["TRIAGE_DECISION_PARSE_FAILED"])
    assert "TRIAGE_DECISION_PARSE_FAILED" in result["unresolved_hops"]


def test_triage_observes_model_tool_evidence_only_for_current_finding(
    source_workflow, triage_request, tmp_path, monkeypatch
):
    (tmp_path / "a.py").write_text(
        "\n" * 9 + "value = request.args['x']\n", encoding="utf-8"
    )
    provider = _FakeProvider()
    tool = _FakeTool()
    workflow = TriageWorkflow(
        llm_provider=provider,
        llama_query_model="dummy",
        toolbox=source_workflow.toolbox,
        plugin_config={},
        model_tools=(tool,),
        model_tool_max_rounds=2,
    )

    result = workflow.triage(triage_request)

    assert result["status"] == "valid"
    assert result["decision_source"] == "model"
    assert result["evidence"] == ["a.py:10"]
    assert provider.chat.bound_tools == [tool]
    assert tool.calls == [{"path": "a.py", "start_line": 8, "end_line": 12}]

    monkeypatch.setattr(
        workflow,
        "_invoke_triage_model",
        Mock(
            return_value=TriageDecisionModel(
                status="invalid",
                reason="The other file rules out the finding.",
                evidence=["a.py:10"],
                resolution_chain=["input -> a.py:10"],
            )
        ),
    )

    repeated = workflow.triage(triage_request)

    assert repeated["status"] == "inconclusive"
    assert repeated["decision_source"] == "validation_failure"
    assert repeated["validation_errors"] == ["UNOBSERVED_CITATION:a.py:10"]
