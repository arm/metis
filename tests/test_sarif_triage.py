# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import CancelledError
from dataclasses import replace
import json
from threading import Event
from unittest.mock import Mock

import pytest

from metis.engine import ExecutionGraphError
from metis.engine.capabilities.navigation import NavigationCapability
from metis.engine.execution import ExecutionStatus
from metis.engine.stages.triage.models import TriageRun
from metis.engine.stages.triage.storage import TriageStore
from metis.sarif.models import SarifPayload
from metis.sarif.triage import apply_triage_annotations
from metis.sarif.triage import apply_triage_result
from metis.sarif.triage import extract_findings
from metis.sarif.triage import TRIAGE_ANNOTATION_KEYS
from metis.sarif.writer import generate_sarif


def test_triage_run_preserves_selected_and_unhandled_findings(engine, node_jobs):
    findings = [
        {"message": {"text": message}} for message in ("prior", "unhandled", "selected")
    ]
    payload = SarifPayload(version="2.1.0", runs=({"results": findings},))
    original = TriageRun.from_payload(payload)
    pending = replace(original, remaining=original.remaining[1:], processed=1)
    classifier = Mock(side_effect=[None, {"status": "invalid", "reason": "Guarded"}])
    result = engine._triage_service.triage_run(
        pending, classifier=classifier, jobs=node_jobs.limit(1)
    )
    assert [call.args[0].message for call in classifier.call_args_list] == [
        "unhandled",
        "selected",
    ]
    assert result.processed == 2 and result.total == 3
    assert result.remaining == (original.remaining[1],)
    findings = result.sarif.runs[0]["results"]
    assert "properties" not in findings[0]
    assert "properties" not in findings[1]
    assert findings[2]["properties"]["metisTriageStatus"] == "invalid"


@pytest.mark.parametrize("source_format", ["review", "sarif"])
def test_streaming_triage_conversion_matches_materialized_output(
    tmp_path, source_format
):
    issues = [
        {
            "id": f"stable-{index}",
            "issue": "Finding",
            "metisTriaged": index == 0,
            "metisTriageStatus": None,
            "metisTriageReason": 123,
            "metisTriageTimestamp": False,
            "custom": {"keep": [None, True, "value"]},
        }
        for index in range(3)
    ]
    payload = (
        {"reviews": [{"file": "source.py", "reviews": issues}]}
        if source_format == "review"
        else {
            "version": "2.1.0",
            "runs": [{"results": [{"properties": issue} for issue in issues]}],
            "reviews": [],
        }
    )
    source = tmp_path / ("input.json" if source_format == "review" else "input.sarif")
    source.write_text(
        json.dumps(payload)[:-1]
        + ',"number":1e-9223372036854775807,"integer":'
        + str(2**100)
        + "}"
    )
    original = source.read_bytes()
    expected = json.loads(original)
    expected_sarif = (
        generate_sarif(expected, read_source=False)
        if source_format == "review"
        else expected
    )
    apply_triage_result(
        expected_sarif, run_index=0, result_index=1, status="valid", reason="Checked"
    )
    annotation = {
        key: value
        for key, value in expected_sarif["runs"][0]["results"][1]["properties"].items()
        if key in TRIAGE_ANNOTATION_KEYS
    }
    if source_format == "review":
        apply_triage_annotations(expected, expected_sarif)
    target, companion = tmp_path / "output.json", tmp_path / "output.sarif"
    with TriageStore(source, destination=target) as store:
        assert store.is_review == (source_format == "review") and store.count() == 2
        store.annotate(next(store.findings()), annotation)
        for path, report in ((target, expected), (companion, expected_sarif)):
            store.publish(path)
            assert json.loads(path.read_text()) == report
    for path, report in ((target, expected), (companion, expected_sarif)):
        assert json.loads(path.read_text()) == report
    assert source.read_bytes() == original


@pytest.mark.parametrize(
    ("filename", "payload", "message"),
    [
        ("input.json", '{"runs":{}}', "Metis reviews array or a SARIF"),
        *[
            (filename, '{"runs":[],"extra":NaN}', "non-finite")
            for filename in ("input.json", "input.sarif")
        ],
        (
            "input.json",
            '{"reviews":[{"file":"source.c","reviews":[{"issue":"Needs triage"}]}],'
            '"reviews":[]}',
            "duplicate mapping key",
        ),
        (
            "input.sarif",
            '{"version":"2.1.0","runs":[{"results":'
            '[{"message":{"text":"Needs triage"}}],"results":[]}]}',
            "duplicate mapping key",
        ),
        (
            "input.json",
            '{"reviews":[{"file":"source.c","reviews":[{"issue":"Needs triage",'
            '"metisTriaged":"false"}]}]}',
            "metisTriaged must be a boolean",
        ),
    ],
)
def test_triage_store_rejects_invalid_input(tmp_path, filename, payload, message):
    source = tmp_path / filename
    source.write_text(payload)

    with pytest.raises(ValueError, match=message), TriageStore(source):
        pass


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


@pytest.mark.parametrize(("flag", "include_triaged"), [("false", False), (1, True)])
def test_triage_run_rejects_non_boolean_completion_flags(flag, include_triaged):
    payload = SarifPayload.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "External"}},
                    "results": [
                        {
                            "message": {"text": "Needs triage"},
                            "properties": {"metisTriaged": flag},
                        }
                    ],
                }
            ],
        }
    )
    with pytest.raises(ValueError, match="metisTriaged must be a boolean"):
        TriageRun.from_payload(payload, include_triaged=include_triaged)


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


def test_triage_payload_preserves_success_and_retries_failed_finding(
    engine, monkeypatch
):
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

    with pytest.raises(ExecutionGraphError, match="Triage failed") as caught:
        engine.execute_triage(payload, progress_callback=progress_events.append)

    execution = caught.value.result
    assert [diagnostic.code for diagnostic in execution.diagnostics] == [
        "triage.finding_failed"
    ]
    out = execution.outputs["triage"]["sarif"]
    first = out["runs"][0]["results"][0]
    second = out["runs"][0]["results"][1]

    assert first["properties"]["metisTriaged"] is True
    assert first["properties"]["metisTriageStatus"] == "valid"
    assert "metisTriageDecisionSource" not in first["properties"]
    assert "metisTriageEvidence" not in first["properties"]
    assert second["properties"]["metisTriaged"] is False
    assert second["properties"]["metisTriageStatus"] == "inconclusive"
    assert (
        "Triage failed before a decision" in second["properties"]["metisTriageReason"]
    )
    assert second["properties"]["metisMissingEvidence"] == ["triage execution failed"]
    assert second["properties"]["metisTriageDecisionSource"] == "execution_failure"
    assert second["properties"]["metisTriageValidationErrors"] == [
        "triage execution failed"
    ]
    triage_events = [
        event
        for event in progress_events
        if event.get("event") in {"start", "progress", "done", "error"}
    ]
    assert [event["event"] for event in triage_events] == [
        "start",
        "progress",
        "done",
        "start",
        "progress",
        "error",
    ]
    assert [
        event["completed"] for event in triage_events if event["event"] == "progress"
    ] == [1, 2]

    retry = engine.execution.execute_triage(out)

    assert retry.status is ExecutionStatus.OK
    assert retry.diagnostics == ()
    assert dummy_workflow.count == 3
    retried_results = retry.outputs["triage"]["sarif"].runs[0]["results"]
    assert retried_results[0] == first
    assert retried_results[1]["properties"]["metisTriaged"] is True
    assert retried_results[1]["properties"]["metisTriageStatus"] == "valid"
    assert "metisTriageDecisionSource" not in retried_results[1]["properties"]


@pytest.mark.parametrize(
    ("decision_source", "validation_errors"),
    [("model", []), ("validation_failure", ["UNOBSERVED_CITATION:unseen.c:1"])],
)
def test_evidence_inconclusive_does_not_fail_execution(
    engine, monkeypatch, decision_source, validation_errors
):
    payload = {
        "version": "2.1.0",
        "runs": [{"results": [{"message": {"text": "A"}, "ruleId": "R1"}]}],
    }

    class _InconclusiveWorkflow:
        def triage(self, _request):
            return {
                "status": "inconclusive",
                "reason": "Caller evidence is unavailable",
                "decision_source": decision_source,
                "validation_errors": validation_errors,
            }

    engine.execution._jobs = engine.execution._scheduler.limit(1)
    monkeypatch.setattr(
        engine._triage_classifier,
        "_workflow",
        lambda _navigation, _rounds, _model=None: _InconclusiveWorkflow(),
    )

    result = engine.execution.execute_triage(payload)

    assert result.status is ExecutionStatus.INCONCLUSIVE
    assert result.diagnostics == ()
    properties = result.outputs["triage"]["sarif"].runs[0]["results"][0]["properties"]
    assert properties["metisTriaged"] is True
    assert properties["metisTriageValidationErrors"] == validation_errors


@pytest.mark.parametrize("decision_source", [None, "model"])
def test_triage_payload_writes_evidence_metadata(engine, monkeypatch, decision_source):
    payload = {
        "version": "2.1.0",
        "runs": [{"results": [{"message": {"text": "A"}, "ruleId": "R1"}]}],
    }

    class _DummyWorkflow:
        def triage(self, _request):
            return {
                "status": "inconclusive",
                "reason": "missing caller",
                "evidence": ["src/a.py:1"],
                "resolution_chain": ["Reported call is present at src/a.py:1"],
                "unresolved_hops": ["Caller definition unavailable"],
                "validation_errors": [],
                **({"decision_source": decision_source} if decision_source else {}),
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

    checkpoints = []
    out = engine.execute_triage(
        payload,
        checkpoint_callback=lambda report, processed, total: checkpoints.append(
            (report, processed, total)
        ),
    )["sarif"]
    assert checkpoints == [(out, 1, 1)]
    props = out["runs"][0]["results"][0]["properties"]

    assert props["metisEvidenceRequirements"] == ["local_context", "use_site"]
    assert props["metisEvidenceCoverage"] == {"local_context": 1, "use_site": 0}
    assert props["metisMissingEvidence"] == ["use_site"]
    assert props["metisTriageEvidence"] == ["src/a.py:1"]
    assert props["metisTriageResolutionChain"] == [
        "Reported call is present at src/a.py:1"
    ]
    assert props["metisTriageUnresolvedHops"] == ["Caller definition unavailable"]
    assert props["metisTriageDecisionSource"] == (decision_source or "policy")
    assert props["metisTriageValidationErrors"] == []
    assert props["metisThreatModelPolicy"] == {
        "claim_type": "caller_contract",
        "disposition": "integration_risk",
    }


@pytest.mark.parametrize("checkpoint_cancels", [False, True])
def test_triage_cancellation_collects_completed_outcomes_before_final_checkpoint(
    engine, node_jobs, checkpoint_cancels
):
    payload = {
        "version": "2.1.0",
        "runs": [
            {"results": [{"message": {"text": text}} for text in ("A", "B", "C")]}
        ],
    }
    run = TriageRun.from_payload(SarifPayload.model_validate(payload))
    cancellation = Event()
    started = Event()
    finished = Event()
    original_error = CancelledError("worker cancellation")
    calls = []

    def classify(finding, *_args):
        calls.append(finding.message)
        if finding.message == "B":
            assert started.wait(5)
            raise original_error
        assert finding.message == "A"
        started.set()
        assert cancellation.wait(5)
        finished.set()
        return {"status": "valid", "reason": "confirmed"}

    checkpoint_calls = []
    snapshots = []

    def save_snapshot(payload, processed, total):
        assert finished.is_set()
        completed, cancelled, queued = payload["runs"][0]["results"]
        assert completed["properties"]["metisTriaged"] is True
        assert "properties" not in cancelled
        assert "properties" not in queued
        checkpoint_calls.append((processed, total))
        if checkpoint_cancels:
            raise CancelledError("checkpoint cancellation")
        snapshots.append(json.loads(json.dumps(payload)))

    with pytest.raises(CancelledError) as raised:
        engine._triage_service.triage_run(
            run,
            classifier=classify,
            jobs=node_jobs.with_cancellation(cancellation),
            checkpoint_callback=save_snapshot,
        )

    assert raised.value is original_error
    assert sorted(calls) == ["A", "B"]
    assert checkpoint_calls == [(1, 1)]
    assert bool(snapshots) is not checkpoint_cancels
    if not checkpoint_cancels:
        saved = snapshots[0]
        assert len(extract_findings(saved)) == 2
        assert saved["runs"][0]["results"][0]["properties"]["metisTriaged"] is True


@pytest.mark.parametrize("cancel_from", ["done", "error", "checkpoint"])
def test_triage_callback_cancellation_preserves_first_completed_finding(
    engine, node_jobs, cancel_from
):
    payload = {
        "version": "2.1.0",
        "runs": [{"results": [{"message": {"text": text}} for text in ("A", "B")]}],
    }
    run = TriageRun.from_payload(SarifPayload.model_validate(payload))
    completed_snapshots = []
    snapshots = []

    def progress(event):
        if event["event"] == cancel_from:
            raise CancelledError("callback cancellation")

    def save_snapshot(payload, processed, total):
        if cancel_from == "checkpoint" and processed < total:
            raise CancelledError("callback cancellation")
        completed_snapshots.append((processed, total))
        snapshots.append(json.loads(json.dumps(payload)))

    classifier = Mock(
        side_effect=RuntimeError("provider failed") if cancel_from == "error" else None,
        return_value={"status": "valid", "reason": "confirmed"},
    )

    with pytest.raises(CancelledError, match="callback cancellation"):
        engine._triage_service.triage_run(
            run,
            classifier=classifier,
            jobs=node_jobs.limit(1),
            progress_callback=progress,
            checkpoint_callback=save_snapshot,
        )

    assert completed_snapshots == [(1, 1)]
    assert classifier.call_count == 1
    saved = snapshots[0]["runs"][0]["results"]
    assert saved[0]["properties"]["metisTriaged"] is (cancel_from != "error")
    assert saved[0]["properties"]["metisTriageStatus"] == (
        "inconclusive" if cancel_from == "error" else "valid"
    )
    assert "properties" not in saved[1]


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


def test_annotation_projection_ignores_malformed_result_collections():
    from metis.sarif.triage import apply_triage_annotations

    report = {"reviews": []}
    for results in (None, 1, True, "text", {}):
        assert (
            apply_triage_annotations(report, {"runs": [{"results": results}]}) is report
        )


def test_negative_annotation_indices_cannot_modify_neighbors():
    payload = {"runs": [{"results": [{}]}]}
    for run_index, result_index in ((-1, 0), (-2, 0), (0, -1), (0, -2)):
        assert not apply_triage_result(
            payload,
            run_index=run_index,
            result_index=result_index,
            status="inconclusive",
            reason="local check",
        )
    assert payload == {"runs": [{"results": [{}]}]}


@pytest.mark.parametrize(
    "replacement_metadata",
    [
        None,
        {
            "evidence": ["src/a.py:1", 42],
            "resolution_chain": [None],
            "unresolved_hops": "unresolved caller",
            "validation_errors": [{}],
            "decision_source": "unknown",
        },
        {"decision_source": []},
    ],
)
def test_retriage_clears_previous_optional_decision_metadata(replacement_metadata):
    payload = {"runs": [{"results": [{"properties": {"metisFindingId": "stable"}}]}]}
    metadata = {
        "evidence": ["src/a.py:1"],
        "resolution_chain": ["Source location inspected"],
        "unresolved_hops": [],
        "decision_source": "model",
        "validation_errors": [],
    }
    assert apply_triage_result(
        payload,
        run_index=0,
        result_index=0,
        status="valid",
        reason="confirmed",
        metadata=metadata,
    )
    properties = payload["runs"][0]["results"][0]["properties"]
    assert properties["metisTriageEvidence"] == metadata["evidence"]
    assert properties["metisTriageEvidence"] is not metadata["evidence"]
    assert apply_triage_result(
        payload,
        run_index=0,
        result_index=0,
        status="invalid",
        reason="legacy classifier result",
        metadata=replacement_metadata,
    )
    properties = payload["runs"][0]["results"][0]["properties"]
    assert properties["metisFindingId"] == "stable"
    assert properties["metisTriageStatus"] == "invalid"
    assert not {
        "metisTriageEvidence",
        "metisTriageResolutionChain",
        "metisTriageUnresolvedHops",
        "metisTriageDecisionSource",
        "metisTriageValidationErrors",
    }.intersection(properties)


@pytest.mark.parametrize("source_tool", ["Metis", "External"])
@pytest.mark.parametrize(
    "uri",
    [
        "https://example.com/a.c",
        "file://remote/a.c",
        "//remote/a.c",
        "file://[",
        "replacement-%FF.c",
        "file:///replacement-%FF.c",
        "bad%ZZ.c",
    ],
)
def test_invalid_uri_retains_finding_without_source_path(uri, source_tool):
    sarif = generate_sarif(
        {"reviews": [{"file": "a.c", "reviews": [{"issue": "Issue"}]}]},
        tool_name=source_tool,
    )
    result = sarif["runs"][0]["results"][0]
    if source_tool == "External":
        result.pop("properties")
    result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = uri

    finding = extract_findings(sarif)[0]

    assert finding.file_path == ""
    assert finding.message == "Issue"


@pytest.mark.parametrize("uri_kind", ["relative", "absolute"])
def test_decoded_sarif_uri_stays_within_navigation_root(tmp_path, uri_kind):
    codebase = tmp_path / "repo"
    codebase.mkdir()
    outside = tmp_path / "outside.c"
    outside.write_text("private\n", encoding="utf-8")
    uri = "%2e%2e/outside.c" if uri_kind == "relative" else outside.as_uri()
    sarif = generate_sarif(
        {"reviews": [{"file": "a.c", "reviews": [{"issue": "Issue"}]}]}
    )
    location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    location["artifactLocation"]["uri"] = uri
    finding = extract_findings(sarif)[0]
    navigation = NavigationCapability(
        codebase_path=str(codebase), timeout_seconds=8, max_chars=16000
    )

    with pytest.raises(ValueError, match="escapes codebase"):
        navigation.sed(finding.file_path, finding.line, finding.line)


@pytest.mark.parametrize(
    ("filename", "decoded_twin"),
    [("literal%20name.c", "literal name.c"), ("literal%2Fname.c", "literal/name.c")],
)
@pytest.mark.parametrize("source_kind", ["metis_154", "metis_155", "metis", "external"])
def test_sarif_literal_percent_paths_read_the_correct_source(
    tmp_path, filename, decoded_twin, source_kind
):
    (tmp_path / filename).write_text("expected();\n", encoding="utf-8")
    twin = tmp_path / decoded_twin
    twin.parent.mkdir(parents=True, exist_ok=True)
    twin.write_text("wrong();\n", encoding="utf-8")
    sarif = generate_sarif(
        {"reviews": [{"file": filename, "reviews": [{"issue": "Issue"}]}]},
        tool_name="External" if source_kind == "external" else "Metis",
    )
    result = sarif["runs"][0]["results"][0]
    if source_kind in {"metis_154", "external"}:
        result["properties"].pop("metisFindingId")
    if source_kind != "metis":
        result["properties"].pop("metisUriEncoding")
    if source_kind in {"metis_154", "metis_155"}:
        sarif["runs"][0]["tool"]["driver"]["version"] = (
            "1.5.4" if source_kind == "metis_154" else "1.5.5"
        )
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = filename
    navigation = NavigationCapability(
        codebase_path=str(tmp_path), timeout_seconds=8, max_chars=16000
    )

    finding = extract_findings(sarif)[0]

    assert finding.file_path == filename
    assert navigation.sed(finding.file_path, finding.line, finding.line) == (
        "1: expected();"
    )
