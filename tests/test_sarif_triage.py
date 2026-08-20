# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.execution import ExecutionStatus
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


def test_triage_payload_marks_failed_finding_inconclusive(engine, monkeypatch):
    progress_events: list[dict[str, object]] = []
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

    class _DummyWorkflow:
        def __init__(self):
            self.count = 0

        def triage(self, _request):
            self.count += 1
            if self.count == 2:
                raise RuntimeError("boom")
            return {"status": "valid", "reason": "confirmed"}

    engine.execution._jobs = engine.execution._scheduler.limit(1)
    dummy_workflow = _DummyWorkflow()
    monkeypatch.setattr(
        engine._triage_classifier,
        "_workflow",
        lambda _navigation, _rounds, _model=None: dummy_workflow,
    )

    out = engine.execute_triage(
        payload,
        progress_callback=progress_events.append,
    )["sarif"]
    first = out["runs"][0]["results"][0]
    second = out["runs"][0]["results"][1]

    assert first["properties"]["metisTriaged"] is True
    assert first["properties"]["metisTriageStatus"] == "valid"
    assert second["properties"]["metisTriaged"] is True
    assert second["properties"]["metisTriageStatus"] == "inconclusive"
    assert (
        "Triage failed before a decision" in second["properties"]["metisTriageReason"]
    )
    assert second["properties"]["metisMissingEvidence"] == ["triage execution failed"]
    triage_events = [
        event
        for event in progress_events
        if event.get("event") in {"start", "progress", "done", "error"}
    ]
    assert [event["event"] for event in triage_events] == [
        "start",
        "progress",
        "start",
        "progress",
        "done",
        "error",
    ]
    assert [
        event["completed"] for event in triage_events if event["event"] == "progress"
    ] == [1, 2]


def test_inconclusive_finding_makes_triage_execution_inconclusive(engine, monkeypatch):
    payload = {
        "version": "2.1.0",
        "runs": [{"results": [{"message": {"text": "A"}, "ruleId": "R1"}]}],
    }

    class _FailingWorkflow:
        def triage(self, _request):
            raise RuntimeError("boom")

    engine.execution._jobs = engine.execution._scheduler.limit(1)
    monkeypatch.setattr(
        engine._triage_classifier,
        "_workflow",
        lambda: _FailingWorkflow(),
    )

    result = engine.execution.execute_triage(payload)

    assert result.status is ExecutionStatus.INCONCLUSIVE
    assert result.diagnostics == ()


def test_triage_payload_writes_evidence_metadata(engine, monkeypatch):
    payload = {
        "version": "2.1.0",
        "runs": [{"results": [{"message": {"text": "A"}, "ruleId": "R1"}]}],
    }

    class _DummyWorkflow:
        def triage(self, _request):
            return {
                "status": "inconclusive",
                "reason": "missing caller",
                "evidence_obligations": ["local_context", "use_site"],
                "evidence_coverage": {"local_context": 1, "use_site": 0},
                "missing_evidence": ["use_site"],
                "threat_model_policy": {
                    "claim_type": "caller_contract",
                    "disposition": "integration_risk",
                },
            }

    monkeypatch.setattr(
        engine._triage_classifier,
        "_workflow",
        lambda _navigation, _rounds, _model=None: _DummyWorkflow(),
    )
    engine.execution._jobs = engine.execution._scheduler.limit(1)

    out = engine.execute_triage(payload)["sarif"]
    props = out["runs"][0]["results"][0]["properties"]

    assert props["metisEvidenceRequirements"] == ["local_context", "use_site"]
    assert props["metisEvidenceCoverage"] == {"local_context": 1, "use_site": 0}
    assert props["metisMissingEvidence"] == ["use_site"]
    assert props["metisThreatModelPolicy"] == {
        "claim_type": "caller_contract",
        "disposition": "integration_risk",
    }


def test_execute_triage_writes_checkpoints_at_configured_cadence(
    engine, monkeypatch, tmp_path
):
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {"message": {"text": letter}, "ruleId": f"R{index}"}
                    for index, letter in enumerate("ABCDE", start=1)
                ]
            }
        ],
    }

    class _DummyWorkflow:
        def triage(self, _request):
            return {"status": "valid", "reason": "confirmed"}

    writes = []

    def save_checkpoint(_path, checkpoint_payload):
        writes.append(
            sum(
                result.get("properties", {}).get("metisTriaged") is True
                for result in checkpoint_payload["runs"][0]["results"]
            )
        )

    monkeypatch.setattr(
        engine._triage_classifier,
        "_workflow",
        lambda _navigation, _rounds, _model=None: _DummyWorkflow(),
    )
    monkeypatch.setattr(
        "metis.engine.stages.triage.service.save_sarif_file",
        save_checkpoint,
    )
    engine.execution._jobs = engine.execution._scheduler.limit(1)
    engine._triage_service.triage_checkpoint_every = 2

    result = engine.execute_triage(
        payload,
        checkpoint_path=str(tmp_path / "checkpoint.sarif"),
    )

    assert writes == [2, 4]
    assert all(
        finding["properties"]["metisTriaged"] is True
        for finding in result["sarif"]["runs"][0]["results"]
    )


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
                                    "artifactLocation": {"uri": "src/a.py"},
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

    class _DummyWorkflow:
        def triage(self, request):
            captured["is_metis"] = request.get("finding_is_metis")
            captured["source_tool"] = request.get("finding_source_tool")
            captured["explanation"] = request.get("finding_explanation")
            return {"status": "valid", "reason": "ok"}

    monkeypatch.setattr(
        engine._triage_classifier,
        "_workflow",
        lambda _navigation, _rounds, _model=None: _DummyWorkflow(),
    )
    engine.execution._jobs = engine.execution._scheduler.limit(1)

    out = engine.execute_triage(payload)["sarif"]
    assert out["runs"][0]["results"][0]["properties"]["metisTriaged"] is True
    assert captured["is_metis"] is True
    assert captured["source_tool"] == "Metis"
    assert "reasoning: Dangerous flow" in str(captured["explanation"])
