# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from pathlib import Path
from concurrent.futures import CancelledError

import json
import pytest
from metis import runlog
from metis.cli import triage_cli
from metis.cli.command_runtime import CommandRuntime
from metis.cli.commands import run_triage
from metis.cli.commands import run_review_code
from metis.cli.utils import save_output
from metis.engine import ExecutionGraphError
from metis.engine.execution import ExecutionDiagnostic
from metis.engine.execution import ExecutionResult
from metis.engine.execution import ExecutionStatus
from metis.engine.stages.triage.models import TriageRun
from metis.engine.stages.triage.service import TriageService
from metis.generated_artifacts import generated_artifact_paths
from metis.sarif.models import SarifPayload
from metis.sarif.writer import generate_sarif


@pytest.mark.parametrize("workflow", ["sarif", "json", "review"])
@pytest.mark.parametrize("checkpoint_every", [0, 50])
def test_cancelled_cli_triage_keeps_completed_decisions(
    tmp_path, workflow, checkpoint_every
):
    results = {
        "reviews": [
            {"file": "source.c", "reviews": [{"issue": "first"}, {"issue": "second"}]}
        ]
    }
    sarif = generate_sarif(results)
    input_path = tmp_path / f"input.{workflow if workflow != 'review' else 'json'}"
    original = json.dumps(sarif if workflow == "sarif" else results)
    input_path.write_text(original)
    output_path = tmp_path / ("output.sarif" if workflow == "sarif" else "output.json")
    cancellation = CancelledError("cancel after first successful finding")

    class InterruptedJobs:
        def run(self, scheduled, invoke, **kwargs):
            first = scheduled[0]
            invoke(first)
            kwargs["on_complete"](first, 1, len(scheduled))
            raise cancellation

    class Engine:
        codebase_path = str(tmp_path)

        def execute_review(self, _mode, **_kwargs):
            return {"formats": ("json",), "findings": results, "sarif": sarif}

        def execute_triage(self, payload, **kwargs):
            service = TriageService(triage_checkpoint_every=checkpoint_every)
            return service.triage_run(
                TriageRun.from_payload(SarifPayload.model_validate(payload)),
                classifier=lambda *_args: {
                    "status": "valid",
                    "reason": "Source confirms finding",
                },
                jobs=InterruptedJobs(),
                checkpoint_callback=service.checkpoint_callback(
                    kwargs["checkpoint_path"]
                ),
            )

    args = SimpleNamespace(
        quiet=True, output_file=[str(output_path)], include_triaged=False, triage=True
    )
    with pytest.raises(CancelledError) as raised:
        if workflow == "review":
            run_review_code(
                Engine(), args, CommandRuntime(command="review_code", command_args=[])
            )
        else:
            run_triage(
                Engine(),
                str(input_path),
                args,
                CommandRuntime(command="triage", command_args=[str(input_path)]),
            )

    assert raised.value is cancellation
    checkpoint = tmp_path / (
        "output.checkpoint.sarif" if workflow == "review" else "output.sarif"
    )
    assert checkpoint.exists() is bool(checkpoint_every)
    if checkpoint_every:
        completed, remaining = json.loads(checkpoint.read_text())["runs"][0]["results"]
        assert completed["properties"]["metisTriaged"] is True
        assert not remaining["properties"].get("metisTriaged")
    assert input_path.read_text() == original
    if workflow == "review":
        saved = json.loads(output_path.read_text())
        assert saved["reviews"][0]["reviews"][0]["issue"] == "first"


@pytest.mark.parametrize(
    ("suffix", "exporter"),
    [
        (".html", "export_html"),
        (".sarif", "export_sarif"),
        (".csv", "export_csv"),
    ],
)
def test_save_output_propagates_export_failure(
    monkeypatch,
    tmp_path,
    suffix,
    exporter,
):
    monkeypatch.setattr(
        f"metis.cli.output.{exporter}",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("write failed")),
    )

    with pytest.raises(RuntimeError, match="write failed"):
        save_output(tmp_path / f"report{suffix}", {"reviews": []}, quiet=True)


@pytest.mark.parametrize("suffix", ("json", "sarif"))
def test_save_output_replaces_json_only_after_serialization_succeeds(tmp_path, suffix):
    output_path = tmp_path / f"report.{suffix}"
    output_path.write_text('{"original": true}', encoding="utf-8")

    with pytest.raises(TypeError):
        save_output(
            output_path,
            {"invalid": object()},
            quiet=True,
            sarif_payload={"invalid": object()},
        )

    assert output_path.read_text(encoding="utf-8") == '{"original": true}'


@pytest.mark.parametrize("format_name", ["json", "sarif"])
def test_save_output_records_written_artifact(tmp_path, format_name):
    trace_path = tmp_path / "trace.ndjson"
    output_path = tmp_path / f"report.{format_name}"
    with runlog.open_runlog(runlog.RunLogConfig(path=trace_path)):
        save_output(output_path, {"reviews": []}, quiet=True, codebase_path=tmp_path)

    records = [
        json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()
    ]
    artifact = next(
        record for record in records if record["name"] == "artifact.written"
    )
    assert artifact["attributes"]["path"] == str(output_path.resolve())
    assert artifact["attributes"]["format"] == format_name
    assert artifact["attributes"]["bytes"] == output_path.stat().st_size
    assert len(artifact["attributes"]["sha256"]) == 64
    assert generated_artifact_paths(tmp_path) == {output_path.resolve()}


@pytest.mark.parametrize(
    ("formats", "filename", "expected_suffixes"),
    [
        (("sarif", "json"), None, {".sarif", ".json"}),
        (("json",), None, {".sarif", ".json"}),
        ((), None, {".sarif"}),
        (("sarif", "json"), "configured", {".sarif", ".json"}),
        ((), "configured", set()),
    ],
)
def test_run_triage_saves_every_configured_format(
    tmp_path,
    monkeypatch,
    formats,
    filename,
    expected_suffixes,
):
    sarif_path = tmp_path / "input.SARIF"
    sarif_path.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
    saved = []
    configured_path = tmp_path / filename if filename else None

    class _DummyEngine:
        execution = SimpleNamespace(
            configuration=SimpleNamespace(
                stages=SimpleNamespace(
                    triage=SimpleNamespace(
                        nodes={
                            "result": SimpleNamespace(
                                filename=str(configured_path) if filename else None,
                                formats=formats,
                            )
                        }
                    )
                )
            )
        )

        def execute_triage(self, payload, **kwargs):
            assert payload["runs"] == []
            assert kwargs.get("options") is None
            assert kwargs["checkpoint_path"] == str(
                configured_path.with_suffix(".sarif") if filename else sarif_path
            )
            return {"formats": formats, "sarif": payload}

    monkeypatch.setattr(
        "metis.cli.output.save_output",
        lambda output_files, *_args, **_kwargs: saved.extend(output_files),
    )

    args = SimpleNamespace(
        quiet=True,
        output_file=None,
        include_triaged=False,
    )
    run_triage(
        _DummyEngine(),
        str(sarif_path),
        args,
        CommandRuntime(
            command="triage",
            command_args=[str(sarif_path)],
        ),
    )

    if filename:
        assert set(saved) == {
            str(configured_path.with_suffix(suffix)) for suffix in expected_suffixes
        }
    else:
        assert str(sarif_path) in saved
    assert {Path(path).suffix.lower() for path in saved} == expected_suffixes


def test_run_triage_checkpoints_next_to_explicit_json_output(tmp_path, monkeypatch):
    sarif_path = tmp_path / "input.sarif"
    output_path = tmp_path / "reports" / "custom.json"
    sarif_path.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")

    class _DummyEngine:
        def execute_triage(self, payload, **kwargs):
            assert kwargs["checkpoint_path"] == str(output_path.with_suffix(".sarif"))
            return {"formats": ("sarif", "json"), "sarif": payload}

    monkeypatch.setattr("metis.cli.output.save_output", lambda *_args, **_kwargs: None)
    args = SimpleNamespace(
        quiet=True,
        output_file=[str(output_path)],
        include_triaged=False,
    )

    run_triage(
        _DummyEngine(),
        str(sarif_path),
        args,
        CommandRuntime(command="triage", command_args=[str(sarif_path)]),
    )


@pytest.mark.parametrize("suffix", ["json", "JSON"])
@pytest.mark.parametrize("source_kind", ["absolute", "symlink"])
def test_run_triage_accepts_metis_json_without_reading_source(
    tmp_path, suffix, source_kind
):
    codebase = tmp_path / "repo"
    codebase.mkdir()
    source_path = tmp_path / "outside.c"
    secret = "outside-codebase-secret"
    source_path.write_text(secret, encoding="utf-8")
    if source_kind == "symlink":
        link = codebase / "linked.c"
        link.symlink_to(source_path)
        source_path = link
    json_path = tmp_path / f"results.{suffix}"
    json_path.write_text(
        json.dumps(
            {
                "reviews": [
                    {
                        "file": "src/a.c",
                        "file_path": str(source_path),
                        "reviews": [
                            {
                                "issue": "Issue A",
                                "line_number": 10,
                                "code_snippet": "supplied();",
                            },
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    class _DummyEngine:
        codebase_path = str(codebase)

        def execute_triage(self, payload, **kwargs):
            assert kwargs.get("options") is None
            assert secret not in json.dumps(payload)
            finding = payload["runs"][0]["results"][0]
            location = finding["locations"][0]["physicalLocation"]
            assert location["region"]["startLine"] == 10
            assert location["region"]["snippet"]["text"] == "supplied();"
            finding["properties"].update(
                {
                    "metisTriaged": True,
                    "metisTriageStatus": "invalid",
                    "metisTriageReason": "Contradicted by source.",
                    "metisTriageTimestamp": "2026-01-01T00:00:00Z",
                }
            )
            return {"formats": ("sarif",), "sarif": payload}

    args = SimpleNamespace(quiet=True, output_file=None, include_triaged=False)

    run_triage(
        _DummyEngine(),
        str(json_path),
        args,
        CommandRuntime(
            command="triage",
            command_args=[str(json_path)],
        ),
    )

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    issue = payload["reviews"][0]["reviews"][0]
    assert issue["metisTriaged"] is True
    assert issue["metisTriageStatus"] == "invalid"
    assert issue["metisTriageReason"] == "Contradicted by source."
    assert secret not in json_path.read_text(encoding="utf-8")
    sarif = json_path.with_suffix(".sarif").read_text(encoding="utf-8")
    assert secret not in sarif


@pytest.mark.parametrize(
    "suffix,destination,save_failure",
    [
        ("json", "input", False),
        ("sarif", "configured", False),
        ("sarif", "explicit", False),
        ("sarif", "configured", True),
    ],
)
def test_triage_saves_partial_annotations_before_raising(
    tmp_path, monkeypatch, suffix, destination, save_failure
):
    results = {
        "reviews": [
            {"file": "source.c", "reviews": [{"id": "stable", "issue": "Completed"}]}
        ]
    }
    input_path = tmp_path / f"findings.{suffix}"
    original = json.dumps(results if suffix == "json" else generate_sarif(results))
    input_path.write_text(original, encoding="utf-8")
    configured_base = tmp_path / "configured"
    output_path = (
        input_path if destination == "input" else tmp_path / f"{destination}.{suffix}"
    )
    partial = generate_sarif(results)
    partial["runs"][0]["results"][0]["properties"].update(
        metisTriaged=True, metisTriageStatus="valid"
    )
    error = ExecutionGraphError(
        ExecutionResult(
            ExecutionStatus.INCONCLUSIVE,
            {"triage": {"sarif": partial}},
            (ExecutionDiagnostic("triage.finding_failed", "provider failed"),),
        )
    )
    messages = []
    stage = (
        SimpleNamespace(
            nodes={
                "private_result": SimpleNamespace(
                    filename=str(configured_base), formats=("json", "sarif")
                )
            }
        )
        if destination != "input"
        else None
    )

    class Engine:
        execution = SimpleNamespace(
            configuration=SimpleNamespace(stages=SimpleNamespace(triage=stage))
        )

        def execute_triage(self, _payload, **kwargs):
            callback = TriageService(triage_checkpoint_every=1).checkpoint_callback(
                kwargs["checkpoint_path"]
            )
            callback(partial, 1, 2)
            raise error

    monkeypatch.setattr(
        "metis.cli.commands.print_console",
        lambda message, *_args: messages.append(message),
    )
    if save_failure:

        def fail_save(*_args, **_kwargs):
            raise OSError("disk full")

        monkeypatch.setattr("metis.cli.output.save_output", fail_save)
    args = SimpleNamespace(
        quiet=True,
        output_file=[str(output_path)] if destination == "explicit" else None,
        include_triaged=False,
    )

    with pytest.raises(ExecutionGraphError) as raised:
        run_triage(
            Engine(),
            str(input_path),
            args,
            CommandRuntime(command="triage", command_args=[str(input_path)]),
        )

    assert raised.value is error
    assert not any("Triage complete" in message for message in messages)
    if destination != "input":
        assert input_path.read_text() == original
    if save_failure:
        assert raised.value.__notes__ == [
            "Saving partial triage output also failed: disk full"
        ]
        assert json.loads(output_path.with_suffix(".sarif").read_text()) == partial
    else:
        saved = json.loads(output_path.read_text())
        properties = (
            saved["reviews"][0]["reviews"]
            if suffix == "json"
            else [result["properties"] for result in saved["runs"][0]["results"]]
        )
        assert properties[0]["metisTriaged"] is True
        assert properties[0]["metisTriageStatus"] == "valid"


@pytest.mark.parametrize("input_format", ["json", "sarif", "external"])
def test_triage_accepts_explicit_format_and_reuses_json_export(tmp_path, input_format):
    input_suffix = "json" if input_format == "json" else "sarif"
    input_path = tmp_path / f"input.{input_suffix}"
    output_path = tmp_path / "output.sarif"
    results = {
        "reviews": [
            {
                "file": "source.c",
                "reviews": [
                    {
                        "id": "existing",
                        "issue": "Already triaged",
                        "metisTriaged": True,
                        "metisTriageStatus": "valid",
                        "metisTriageEvidence": ["source.c:1"],
                    }
                ],
            }
        ]
    }
    source_payload = (
        results
        if input_suffix == "json"
        else generate_sarif(results, read_source=False)
    )
    if input_format == "external":
        source_payload["runs"][0]["tool"]["driver"]["name"] = "External analyzer"
        source_payload["runs"][0]["results"][0].pop("ruleId", None)
        source_payload["runs"][0]["properties"] = {"externalMetadata": "retained"}
    input_path.write_text(
        json.dumps(source_payload),
        encoding="utf-8",
    )

    class _DummyEngine:
        def execute_triage(self, payload, **kwargs):
            assert kwargs["checkpoint_path"] == str(output_path)
            return {"formats": ("json",), "sarif": payload}

    args = SimpleNamespace(
        quiet=True,
        output_file=[str(output_path)],
        include_triaged=False,
    )

    run_triage(
        _DummyEngine(),
        str(input_path),
        args,
        CommandRuntime(command="triage", command_args=[str(input_path)]),
    )

    assert json.loads(output_path.read_text())["version"] == "2.1.0"
    json_path = output_path.with_suffix(".json")
    exported = json.loads(json_path.read_text())
    assert exported == (results if input_suffix == "json" else source_payload)

    args.output_file = None
    run_triage(
        _DummyEngine(),
        str(json_path),
        args,
        CommandRuntime(command="triage", command_args=[str(json_path)]),
    )

    assert json.loads(json_path.read_text()) == exported


@pytest.mark.parametrize(
    ("filename", "payload", "error", "message"),
    [
        ("input.json", '{"runs":{}}', ValueError, "Metis reviews array or a SARIF"),
        (
            "input.json",
            '{"reviews":[{"file":"source.c","reviews":[{"issue":"Needs triage"}]}],'
            '"reviews":[]}',
            ValueError,
            "duplicate mapping key",
        ),
        *[
            (
                filename,
                '{"version":"2.1.0","runs":[{"results":'
                '[{"message":{"text":"Needs triage"}}],"results":[]}]}',
                ValueError,
                "duplicate mapping key",
            )
            for filename in ("input.json", "input.sarif")
        ],
        (
            "input.json",
            '{"reviews":[{"file":"source.c","reviews":[{"issue":"Needs triage",'
            '"metisTriaged":"false"}]}]}',
            ValueError,
            "metisTriaged must be a boolean",
        ),
        ("input.txt", "text", ValueError, "Only .sarif and .json"),
        ("missing.sarif", None, FileNotFoundError, "File not found"),
    ],
)
def test_run_triage_rejects_invalid_input(tmp_path, filename, payload, error, message):
    input_path = tmp_path / filename
    if payload is not None:
        input_path.write_text(payload, encoding="utf-8")
    args = SimpleNamespace(quiet=False, output_file=None, include_triaged=False)

    with pytest.raises(error, match=message):
        run_triage(
            object(),
            str(input_path),
            args,
            CommandRuntime(command="triage", command_args=[str(input_path)]),
        )
    if payload is not None:
        assert input_path.read_text(encoding="utf-8") == payload


def test_save_output_json_matches_triage_annotations_by_identity(tmp_path):
    output_path = tmp_path / "results.json"
    results = {
        "reviews": [
            {
                "file": "src/a.c",
                "reviews": [
                    {"id": "finding-a", "issue": "Issue A", "line_number": 10},
                    {"id": "finding-b", "issue": "Issue B", "line_number": 10},
                ],
            }
        ]
    }
    triaged_sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "properties": {
                            "metisFindingId": "finding-b",
                            "metisTriaged": True,
                            "metisTriageStatus": "invalid",
                            "metisTriageReason": "Contradicted by code.",
                            "metisTriageTimestamp": "2026-01-01T00:00:02Z",
                        },
                    },
                    {
                        "properties": {
                            "metisFindingId": "finding-a",
                            "metisTriaged": True,
                            "metisTriageStatus": "valid",
                            "metisTriageReason": "Concrete evidence found.",
                            "metisTriageTimestamp": "2026-01-01T00:00:03Z",
                            "metisThreatModelPolicy": {"claims": ["scope"]},
                            "severity": "unrelated property",
                        },
                    },
                ]
            }
        ],
    }

    results["reviews"][0]["reviews"][0]["metisTriageEvidence"] = ["obsolete.c:1"]
    save_output(str(output_path), results, quiet=True, sarif_payload=triaged_sarif)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    issues = payload["reviews"][0]["reviews"]
    assert issues[0]["issue"] == "Issue A"
    assert issues[0]["metisTriageStatus"] == "valid"
    assert "metisTriageEvidence" not in issues[0]
    assert "severity" not in issues[0]
    assert issues[0]["metisThreatModelPolicy"] == {"claims": ["scope"]}
    properties = triaged_sarif["runs"][0]["results"][1]["properties"]
    properties["metisThreatModelPolicy"]["claims"].append("later mutation")
    assert results["reviews"][0]["reviews"][0]["metisThreatModelPolicy"] == {
        "claims": ["scope"]
    }
    assert issues[1]["issue"] == "Issue B"
    assert issues[1]["metisTriageStatus"] == "invalid"


@pytest.mark.parametrize(
    ("report_ids", "sarif_ids"),
    [
        (("duplicate", "duplicate"), ("duplicate",)),
        (("duplicate",), ("duplicate", "duplicate")),
    ],
)
def test_save_output_ignores_ambiguous_finding_ids(
    tmp_path: Path,
    report_ids: tuple[str, ...],
    sarif_ids: tuple[str, ...],
) -> None:
    output_path = tmp_path / "results.json"
    results = {
        "reviews": [
            {
                "reviews": [
                    {"id": finding_id, "issue": f"Issue {index}"}
                    for index, finding_id in enumerate(report_ids)
                ]
            }
        ]
    }
    triaged_sarif = {
        "runs": [
            {
                "results": [
                    {
                        "properties": {
                            "metisFindingId": finding_id,
                            "metisTriaged": True,
                        }
                    }
                    for finding_id in sarif_ids
                ]
            }
        ]
    }

    save_output(output_path, results, quiet=True, sarif_payload=triaged_sarif)

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert all("metisTriaged" not in issue for issue in saved["reviews"][0]["reviews"])


def test_triage_debug_callback_enabled_without_verbose():
    args = SimpleNamespace(log_level="DEBUG", verbose=False, quiet=True)

    callback = triage_cli._make_triage_debug_callback(args)

    assert callable(callback)


def test_triage_debug_callback_ignores_quiet(monkeypatch):
    args = SimpleNamespace(log_level="DEBUG", verbose=False, quiet=True)
    calls = []

    monkeypatch.setattr(
        triage_cli,
        "print_console",
        lambda message, quiet=False, **kwargs: calls.append((str(message), quiet)),
    )

    callback = triage_cli._make_triage_debug_callback(args)
    callback(
        {"event": "model_output", "decision_status": "valid", "decision_reason": "ok"}
    )

    assert calls
    assert all(quiet is False for _message, quiet in calls)
