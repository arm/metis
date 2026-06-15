# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
from langchain_core.messages import AIMessage

from metis.engine.graphs.triage import TriageGraph
from metis.engine.graphs.triage.llm import _build_user_prompt
from metis.engine.graphs.schemas import TriageDecisionModel


class _App:
    def __init__(self, payload):
        self.payload = payload
        self.last_input = None

    def invoke(self, state):
        self.last_input = state
        return self.payload


class _FakeTool:
    name = "sed"
    description = "Read line window."
    metadata = {"metis_contract": "Navigation contract", "metis_contract_max_chars": 80}

    def __init__(self):
        self.calls = []

    def invoke(self, args):
        self.calls.append(args)
        return "a.py:10:value = request.args['x']"


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


def _build_graph():
    return TriageGraph(
        llm_provider=object(),
        llama_query_model="dummy",
        toolbox=object(),
        plugin_config={},
    )


def test_triage_schema_allows_inconclusive_with_unresolved_hops():
    decision = TriageDecisionModel(
        status="inconclusive",
        reason="wrapper chain unresolved",
        evidence=[],
        resolution_chain=["reported finding -> PROJECT_STACK_ALLOC(...)"],
        unresolved_hops=["PROJECT_STACK_ALLOC macro expansion unknown"],
    )
    assert decision.status == "inconclusive"


def test_triage_graph_invokes_navigation_model_tool_before_decision():
    provider = _FakeProvider()
    tool = _FakeTool()
    graph = TriageGraph(
        llm_provider=provider,
        llama_query_model="dummy",
        toolbox=object(),
        plugin_config={},
        model_tools=(tool,),
        model_tool_max_rounds=2,
    )

    decision = graph._invoke_triage_model(
        "You triage findings.",
        "Validate this finding with navigation evidence.",
    )

    assert decision.status == "valid"
    assert provider.chat.bound_tools == [tool]
    assert tool.calls == [{"path": "a.py", "start_line": 8, "end_line": 12}]


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
        }
    )

    assert "Language Context:" in prompt
    assert "- language: python" in prompt
    assert "Inspect decorators and validators first." in prompt


def test_triage_schema_rejects_inconclusive_without_unresolved_hops():
    with pytest.raises(ValueError):
        TriageDecisionModel(
            status="inconclusive",
            reason="uncertain",
            evidence=[],
            resolution_chain=["x -> y"],
            unresolved_hops=[],
        )


def test_triage_graph_accepts_inconclusive(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "inconclusive",
                "decision_reason": "chain unresolved",
                "decision_evidence": [],
                "decision_resolution_chain": ["finding -> wrapper"],
                "decision_unresolved_hops": ["wrapper definition missing"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "inconclusive"


def test_triage_graph_fills_unresolved_hops_for_inconclusive(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "inconclusive",
                "decision_reason": "chain unresolved",
                "decision_evidence": [],
                "decision_resolution_chain": ["finding -> wrapper"],
                "decision_unresolved_hops": ["wrapper target unresolved"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "inconclusive"
    assert out["unresolved_hops"] == ["wrapper target unresolved"]


def test_triage_graph_keeps_inconclusive_when_uncertainty_exists(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "inconclusive",
                "decision_reason": "insufficient evidence; cannot determine.",
                "decision_evidence": ["a.c:10"],
                "decision_resolution_chain": ["finding -> symbol -> site"],
                "decision_unresolved_hops": ["macro expansion unresolved"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "inconclusive"


def test_triage_graph_allows_valid_with_non_critical_unresolved_hops(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": "evidence chain is present with direct citations.",
                "decision_evidence": ["a.c:10", "a.c:30"],
                "decision_resolution_chain": ["source -> guard -> sink"],
                "decision_unresolved_hops": ["FLOW_SINK_CLASS_UNRESOLVED:helper_call"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "valid"


def test_triage_graph_keeps_inconclusive_with_critical_unresolved_hops(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": "evidence chain is present with direct citations.",
                "decision_evidence": ["a.c:10", "a.c:30"],
                "decision_resolution_chain": ["source -> guard -> sink"],
                "decision_unresolved_hops": ["FLOW_SINK_NOT_FOUND"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "inconclusive"


def test_triage_graph_allows_valid_when_macro_unresolved_hop_is_resolved(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": "evidence chain is present with direct citations.",
                "decision_evidence": [
                    "a.c:10",
                    "a.c:30",
                    "MACRO_RESOLUTION PROJECT_STACK_ALLOC -> alloca",
                ],
                "decision_resolution_chain": [
                    "source -> guard -> sink",
                    "MACRO_RESOLUTION PROJECT_STACK_ALLOC -> alloca",
                ],
                "decision_unresolved_hops": [
                    "MACRO_DEFINITION_UNRESOLVED:PROJECT_STACK_ALLOC"
                ],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 1,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "valid"


def test_triage_graph_does_not_force_inconclusive_for_assumption_findings(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": "concrete citations and full chain show issue.",
                "decision_evidence": ["a.c:75", "a.c:102"],
                "decision_resolution_chain": [
                    "reported helper -> run wrapper -> kernel call"
                ],
                "decision_unresolved_hops": [],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "Use of PROJECT_ASSUME instead of runtime checks allows undefined behavior",
            "finding_file_path": "a.c",
            "finding_line": 75,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "valid"


def test_triage_graph_does_not_upgrade_invalid_to_valid(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "invalid",
                "decision_reason": "false positive due to dominating assignment",
                "decision_evidence": ["a.c:10", "a.c:20"],
                "decision_resolution_chain": ["source -> assignment -> sink"],
                "decision_unresolved_hops": [],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 10,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "invalid"


def test_triage_graph_does_not_treat_unbounded_as_bounded_contradiction(
    monkeypatch,
):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": (
                    "The finding is valid because an unbounded receiver_count "
                    "is used without overflow checking."
                ),
                "decision_evidence": ["a.c:10", "a.c:20"],
                "decision_resolution_chain": ["reported count -> size calculation"],
                "decision_unresolved_hops": [],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "unchecked size calculation",
            "finding_file_path": "a.c",
            "finding_line": 10,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "valid"
    assert "OVERRIDE_CONTRADICTION_SIGNAL" not in out["reason"]


def test_triage_graph_does_not_treat_bounded_table_as_contradiction(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": (
                    "The finding is valid because the bounded table is indexed "
                    "without a runtime validation path."
                ),
                "decision_evidence": ["a.c:10", "a.c:20"],
                "decision_resolution_chain": ["reported index -> table access"],
                "decision_unresolved_hops": [],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "unchecked table index",
            "finding_file_path": "a.c",
            "finding_line": 10,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "valid"
    assert "OVERRIDE_CONTRADICTION_SIGNAL" not in out["reason"]


def test_triage_graph_does_not_treat_negated_contradiction_as_invalid(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": (
                    "The finding is valid. The unresolved platform contract "
                    "does not contradict the absence of a local bounds check."
                ),
                "decision_evidence": ["a.c:10", "a.c:20"],
                "decision_resolution_chain": ["reported index -> table access"],
                "decision_unresolved_hops": [],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "unchecked table index",
            "finding_file_path": "a.c",
            "finding_line": 10,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "valid"
    assert "OVERRIDE_CONTRADICTION_SIGNAL" not in out["reason"]


def test_triage_graph_applies_evidence_gate_override(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "valid",
                "decision_reason": "looks valid",
                "decision_evidence": ["a.c:10"],
                "decision_resolution_chain": ["source -> sink"],
                "decision_unresolved_hops": [],
                "evidence_gate_missing": ["FILE_CONTEXT_MISSING"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 10,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "inconclusive"
    assert "OVERRIDE_EVIDENCE_GATE_INCOMPLETE" in out["reason"]
    assert out["missing_evidence"] == ["FILE_CONTEXT_MISSING"]


def test_triage_graph_applies_status_specific_obligation_gate(monkeypatch):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "invalid",
                "decision_reason": "strong contradiction in observed flow",
                "decision_evidence": ["a.c:10", "a.c:20"],
                "decision_resolution_chain": ["source -> guard -> sink"],
                "decision_unresolved_hops": [],
                "evidence_obligations": [
                    "local_context",
                    "symbol_definition",
                    "constraint_or_guard",
                ],
                "obligation_coverage": {
                    "local_context": 1,
                    "symbol_definition": 1,
                    "constraint_or_guard": 0,
                },
                "obligation_missing": ["constraint_or_guard"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 10,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "inconclusive"
    assert "OVERRIDE_OBLIGATION_COVERAGE" in out["reason"]
    assert out["missing_evidence"] == []


def test_triage_graph_relaxes_invalid_constraint_gate_when_core_evidence_present(
    monkeypatch,
):
    g = _build_graph()
    monkeypatch.setattr(
        g,
        "_get_app",
        lambda: _App(
            {
                "decision_status": "invalid",
                "decision_reason": "concrete local contradiction in observed flow",
                "decision_evidence": ["a.c:10", "a.c:20"],
                "decision_resolution_chain": ["source -> check -> sink"],
                "decision_unresolved_hops": [],
                "evidence_obligations": [
                    "local_context",
                    "symbol_definition",
                    "use_site",
                    "constraint_or_guard",
                ],
                "obligation_coverage": {
                    "local_context": 1,
                    "symbol_definition": 2,
                    "use_site": 1,
                    "constraint_or_guard": 0,
                },
                "obligation_missing": ["constraint_or_guard"],
            }
        ),
    )
    out = g.triage(
        {
            "finding_message": "msg",
            "finding_file_path": "a.c",
            "finding_line": 10,
            "finding_rule_id": "R1",
            "finding_snippet": "",
        }
    )
    assert out["status"] == "invalid"
    assert "OVERRIDE_OBLIGATION_COVERAGE" not in out["reason"]
