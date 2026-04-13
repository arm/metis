# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace

import pytest

from metis.sarif.triage import extract_findings


def test_extract_findings_reads_result_fields():
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "X001",
                        "message": {"text": "Potential issue"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/main.c"},
                                    "region": {
                                        "startLine": 42,
                                        "snippet": {"text": "danger();"},
                                    },
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }

    findings = extract_findings(payload)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "X001"
    assert finding.message == "Potential issue"
    assert finding.file_path == "src/main.c"
    assert finding.line == 42
    assert finding.snippet == "danger();"
    assert finding.source_tool == ""
    assert finding.is_metis_source is False
    assert finding.explanation == ""


def test_extract_findings_marks_metis_source_and_explanation():
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Metis", "fullName": "Metis v1.2.0"}},
                "results": [
                    {
                        "ruleId": "X001",
                        "message": {"text": "Potential issue"},
                        "properties": {
                            "reasoning": "Flow can reach sink",
                            "why": "Input is not checked",
                            "mitigation": "Add bounds check",
                        },
                    }
                ],
            }
        ],
    }

    findings = extract_findings(payload)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_tool == "Metis"
    assert finding.is_metis_source is True
    assert "reasoning: Flow can reach sink" in finding.explanation
    assert "mitigation: Add bounds check" in finding.explanation


def test_extract_findings_skips_metis_triaged_by_default():
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {"ruleId": "R1", "message": {"text": "fresh"}},
                    {
                        "ruleId": "R2",
                        "message": {"text": "already"},
                        "properties": {"metisTriaged": True},
                    },
                ]
            }
        ],
    }

    findings = extract_findings(payload)
    assert len(findings) == 1
    assert findings[0].rule_id == "R1"


def test_extract_findings_can_include_metis_triaged():
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {"ruleId": "R1", "message": {"text": "fresh"}},
                    {
                        "ruleId": "R2",
                        "message": {"text": "already"},
                        "properties": {"metisTriaged": True},
                    },
                ]
            }
        ],
    }

    findings = extract_findings(payload, include_triaged=True)
    assert len(findings) == 2


def test_triage_payload_skips_failed_finding(engine, monkeypatch):
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {"message": {"text": "A"}, "ruleId": "R1"},
                    {"message": {"text": "B"}, "ruleId": "R2"},
                ]
            }
        ],
    }

    class _DummyGraph:
        def __init__(self):
            self.count = 0

        def triage(self, _request):
            self.count += 1
            if self.count == 2:
                raise RuntimeError("boom")
            return {"status": "valid", "reason": "confirmed"}

    monkeypatch.setattr(
        engine._triage_service,
        "_init_and_get_triage_query_engines",
        lambda: (SimpleNamespace(), SimpleNamespace()),
    )
    engine.max_workers = 1
    engine._triage_service.max_workers = 1
    dummy_graph = _DummyGraph()
    monkeypatch.setattr(
        engine._triage_service, "_get_thread_triage_graph", lambda: dummy_graph
    )

    out = engine.triage_sarif_payload(payload)
    first = out["runs"][0]["results"][0]
    second = out["runs"][0]["results"][1]

    assert first["properties"]["metisTriaged"] is True
    assert first["properties"]["metisTriageStatus"] == "valid"
    assert "properties" not in second


def test_triage_file_writes_checkpoints(engine, monkeypatch, tmp_path):
    input_path = tmp_path / "findings.sarif"
    input_path.write_text(
        (
            '{"version":"2.1.0","runs":[{"results":['
            '{"message":{"text":"A"},"ruleId":"R1"},'
            '{"message":{"text":"B"},"ruleId":"R2"},'
            '{"message":{"text":"C"},"ruleId":"R3"},'
            '{"message":{"text":"D"},"ruleId":"R4"},'
            '{"message":{"text":"E"},"ruleId":"R5"}'
            "]}]}"
        ),
        encoding="utf-8",
    )

    class _DummyGraph:
        def triage(self, _request):
            return {"status": "valid", "reason": "confirmed"}

    writes = []

    def _save(_path, payload):
        triaged_count = 0
        for result in payload.get("runs", [{}])[0].get("results", []):
            props = result.get("properties", {})
            if props.get("metisTriaged") is True:
                triaged_count += 1
        writes.append(triaged_count)

    monkeypatch.setattr(
        engine._triage_service,
        "_init_and_get_triage_query_engines",
        lambda: (SimpleNamespace(), SimpleNamespace()),
    )
    monkeypatch.setattr(
        engine._triage_service, "_get_thread_triage_graph", lambda: _DummyGraph()
    )
    monkeypatch.setattr("metis.engine.triage_service_exec.save_sarif_file", _save)
    engine.max_workers = 1
    engine._triage_service.max_workers = 1

    out_path = engine.triage_sarif_file(str(input_path), checkpoint_every=2)

    assert out_path == str(input_path)
    assert writes == [2, 4, 5]


def test_triage_payload_no_index_skips_query_engine_init(engine, monkeypatch):
    payload = {
        "version": "2.1.0",
        "runs": [{"results": [{"message": {"text": "A"}, "ruleId": "R1"}]}],
    }

    class _DummyGraph:
        def triage(self, request):
            assert request["use_retrieval_context"] is False
            assert request["retriever_code"] is None
            assert request["retriever_docs"] is None
            return {"status": "valid", "reason": "confirmed"}

    monkeypatch.setattr(
        engine._triage_service,
        "_init_and_get_triage_query_engines",
        lambda: (_ for _ in ()).throw(
            AssertionError("should not initialize query engines")
        ),
    )
    monkeypatch.setattr(
        engine._triage_service, "_get_thread_triage_graph", lambda: _DummyGraph()
    )
    engine._triage_service.max_workers = 1

    out = engine.triage_sarif_payload(payload, use_retrieval_context=False)

    result = out["runs"][0]["results"][0]
    assert result["properties"]["metisTriaged"] is True


def test_triage_payload_raises_when_query_engine_init_fails(engine, monkeypatch):
    payload = {
        "version": "2.1.0",
        "runs": [{"results": [{"message": {"text": "A"}, "ruleId": "R1"}]}],
    }

    monkeypatch.setattr(
        engine._triage_service,
        "_init_and_get_triage_query_engines",
        lambda: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    with pytest.raises(RuntimeError, match="boom"):
        engine.triage_sarif_payload(payload)


def test_triage_request_propagates_source_metadata(engine, monkeypatch):
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "message": {"text": "A"},
                        "ruleId": "R1",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/a.c"},
                                    "region": {"startLine": 12},
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }

    captured = {}

    class _DummyGraph:
        def triage(self, request):
            captured["is_metis"] = request.get("finding_is_metis")
            captured["source_tool"] = request.get("finding_source_tool")
            return {"status": "valid", "reason": "ok"}

    monkeypatch.setattr(
        engine._triage_service,
        "_init_and_get_triage_query_engines",
        lambda: (SimpleNamespace(), SimpleNamespace()),
    )
    monkeypatch.setattr(
        engine._triage_service, "_get_thread_triage_graph", lambda: _DummyGraph()
    )
    engine.max_workers = 1
    engine._triage_service.max_workers = 1

    out = engine.triage_sarif_payload(payload)
    assert out["runs"][0]["results"][0]["properties"]["metisTriaged"] is True
    assert captured["is_metis"] is False
    assert captured["source_tool"] == ""


def test_triage_request_propagates_metis_source_hints(engine, monkeypatch):
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Metis", "fullName": "Metis v1.2.0"}},
                "results": [
                    {
                        "message": {"text": "A"},
                        "ruleId": "R1",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/a.c"},
                                    "region": {"startLine": 12},
                                }
                            }
                        ],
                        "properties": {
                            "reasoning": "Dangerous flow",
                            "mitigation": "Add check",
                        },
                    }
                ],
            }
        ],
    }

    captured = {}

    class _DummyGraph:
        def triage(self, request):
            captured["is_metis"] = request.get("finding_is_metis")
            captured["source_tool"] = request.get("finding_source_tool")
            captured["explanation"] = request.get("finding_explanation")
            return {"status": "valid", "reason": "ok"}

    monkeypatch.setattr(
        engine._triage_service,
        "_init_and_get_triage_query_engines",
        lambda: (SimpleNamespace(), SimpleNamespace()),
    )
    monkeypatch.setattr(
        engine._triage_service, "_get_thread_triage_graph", lambda: _DummyGraph()
    )
    engine.max_workers = 1
    engine._triage_service.max_workers = 1

    out = engine.triage_sarif_payload(payload)
    assert out["runs"][0]["results"][0]["properties"]["metisTriaged"] is True
    assert captured["is_metis"] is True
    assert captured["source_tool"] == "Metis"
    assert "reasoning: Dangerous flow" in str(captured["explanation"])
