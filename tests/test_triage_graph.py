# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.graphs.triage import TriageGraph
from metis.engine.graphs.schemas import TriageDecisionModel


class _App:
    def __init__(self, payload):
        self.payload = payload

    def invoke(self, _):
        return self.payload


def _build_graph():
    return TriageGraph(
        llm_provider=object(),
        llama_query_model="dummy",
        tool_runner=object(),
        plugin_config={},
    )


def test_triage_schema_allows_inconclusive_with_unresolved_hops():
    decision = TriageDecisionModel(
        status="inconclusive",
        reason="wrapper chain unresolved",
        evidence=[],
        resolution_chain=["reported finding -> ALLOCA(...)"],
        unresolved_hops=["ALLOCA macro expansion unknown"],
    )
    assert decision.status == "inconclusive"


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
            "retriever_code": object(),
            "retriever_docs": object(),
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
                "decision_unresolved_hops": [],
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
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "inconclusive"
    assert out["unresolved_hops"]


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
            "retriever_code": object(),
            "retriever_docs": object(),
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
            "retriever_code": object(),
            "retriever_docs": object(),
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
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "inconclusive"


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
            "finding_message": "Use of KAI_ASSUME instead of runtime checks allows undefined behavior",
            "finding_file_path": "a.c",
            "finding_line": 75,
            "finding_rule_id": "R1",
            "finding_snippet": "",
            "retriever_code": object(),
            "retriever_docs": object(),
        }
    )
    assert out["status"] == "valid"
