# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from pathlib import Path

import json
import pytest
from metis import runlog
from metis.cli import triage_cli
from metis.cli.command_runtime import CommandRuntime
from metis.cli.commands import run_triage
from metis.cli.utils import save_output
from metis.sarif.utils import create_fingerprint


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
        f"metis.cli.utils.{exporter}",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("write failed")),
    )

    with pytest.raises(RuntimeError, match="write failed"):
        save_output(tmp_path / f"report{suffix}", {"reviews": []}, quiet=True)


def test_save_output_replaces_json_only_after_serialization_succeeds(tmp_path):
    output_path = tmp_path / "report.json"
    output_path.write_text('{"original": true}', encoding="utf-8")

    with pytest.raises(TypeError):
        save_output(output_path, {"invalid": object()}, quiet=True)

    assert output_path.read_text(encoding="utf-8") == '{"original": true}'


def test_save_output_records_written_artifact(tmp_path):
    trace_path = tmp_path / "trace.ndjson"
    output_path = tmp_path / "report.json"
    with runlog.open_runlog(runlog.RunLogConfig(path=trace_path)):
        save_output(output_path, {"reviews": []}, quiet=True)

    records = [
        json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()
    ]
    artifact = next(
        record for record in records if record["name"] == "artifact.written"
    )
    assert artifact["attributes"]["path"] == str(output_path.resolve())
    assert artifact["attributes"]["format"] == "json"
    assert artifact["attributes"]["bytes"] == output_path.stat().st_size
    assert len(artifact["attributes"]["sha256"]) == 64


@pytest.mark.parametrize(
    ("formats", "expected_suffixes"),
    [
        (("sarif", "json"), {".sarif", ".json"}),
        (("json",), {".json"}),
        ((), set()),
    ],
)
def test_run_triage_saves_every_configured_format(
    tmp_path,
    monkeypatch,
    formats,
    expected_suffixes,
):
    sarif_path = tmp_path / "input.sarif"
    sarif_path.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
    saved = []

    class _DummyEngine:
        def execute_triage(self, payload, **kwargs):
            assert payload["runs"] == []
            assert kwargs.get("options") is None
            assert kwargs["checkpoint_path"] == str(sarif_path)
            return {"formats": formats, "sarif": payload}

    monkeypatch.setattr(
        "metis.cli.commands.save_output",
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

    assert {Path(path).suffix for path in saved} == expected_suffixes


def test_run_triage_checkpoints_next_to_explicit_json_output(tmp_path, monkeypatch):
    sarif_path = tmp_path / "input.sarif"
    output_path = tmp_path / "reports" / "custom.json"
    sarif_path.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")

    class _DummyEngine:
        def execute_triage(self, payload, **kwargs):
            assert kwargs["checkpoint_path"] == str(output_path.with_suffix(".sarif"))
            return {"formats": ("sarif", "json"), "sarif": payload}

    monkeypatch.setattr(
        "metis.cli.commands.save_output", lambda *_args, **_kwargs: None
    )
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


def test_run_triage_accepts_metis_json_input(tmp_path):
    json_path = tmp_path / "results.json"
    json_path.write_text(
        json.dumps(
            {
                "reviews": [
                    {
                        "file": "src/a.c",
                        "reviews": [{"issue": "Issue A", "line_number": 10}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    class _DummyEngine:
        def execute_triage(self, payload, **kwargs):
            assert kwargs.get("options") is None
            payload["runs"][0]["results"][0]["properties"] = {
                "metisTriaged": True,
                "metisTriageStatus": "invalid",
                "metisTriageReason": "Contradicted by source.",
                "metisTriageTimestamp": "2026-01-01T00:00:00Z",
            }
            return {"formats": ("json",), "sarif": payload}

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


def test_json_triage_rejects_format_not_declared_by_graph(tmp_path):
    json_path = tmp_path / "results.json"
    output_path = tmp_path / "results.sarif"
    json_path.write_text('{"reviews":[]}', encoding="utf-8")

    class _DummyEngine:
        def execute_triage(self, payload, **_kwargs):
            return {"formats": ("json",), "sarif": payload}

    args = SimpleNamespace(
        quiet=True,
        output_file=[str(output_path)],
        include_triaged=False,
    )

    with pytest.raises(ValueError, match="did not request sarif output"):
        run_triage(
            _DummyEngine(),
            str(json_path),
            args,
            CommandRuntime(command="triage", command_args=[str(json_path)]),
        )


def test_run_triage_rejects_non_metis_json_input(tmp_path, monkeypatch):
    json_path = tmp_path / "input.json"
    json_path.write_text('{"runs":[]}', encoding="utf-8")
    messages = []

    monkeypatch.setattr(
        "metis.cli.commands.print_console",
        lambda message, quiet=False: messages.append(str(message)),
    )

    args = SimpleNamespace(quiet=False, output_file=None, include_triaged=False)

    run_triage(
        object(),
        str(json_path),
        args,
        CommandRuntime(
            command="triage",
            command_args=[str(json_path)],
        ),
    )

    assert any("Metis results object" in message for message in messages)


def test_save_output_json_includes_triage_annotations(tmp_path):
    output_path = tmp_path / "results.json"
    results = {
        "reviews": [
            {
                "file": "src/a.c",
                "reviews": [
                    {"issue": "Issue A", "line_number": 10},
                    {"issue": "Issue B", "line_number": 20},
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
                        "ruleId": "AI001",
                        "message": {"text": "Issue A"},
                        "partialFingerprints": {
                            "primaryLocationLineHash": create_fingerprint(
                                "src/a.c", 10, "AI001"
                            )
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/a.c"},
                                    "region": {"startLine": 10},
                                }
                            }
                        ],
                        "properties": {
                            "metisTriaged": True,
                            "metisTriageStatus": "valid",
                            "metisTriageReason": "Concrete evidence found.",
                            "metisTriageTimestamp": "2026-01-01T00:00:00Z",
                        },
                    },
                    {
                        "ruleId": "AI001",
                        "message": {"text": "Issue B"},
                        "partialFingerprints": {
                            "primaryLocationLineHash": create_fingerprint(
                                "src/a.c", 20, "AI001"
                            )
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/a.c"},
                                    "region": {"startLine": 20},
                                }
                            }
                        ],
                        "properties": {
                            "metisTriaged": True,
                            "metisTriageStatus": "inconclusive",
                            "metisTriageReason": "Alias chain unresolved.",
                            "metisTriageTimestamp": "2026-01-01T00:00:01Z",
                        },
                    },
                ]
            }
        ],
    }

    save_output(str(output_path), results, quiet=True, sarif_payload=triaged_sarif)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    issues = payload["reviews"][0]["reviews"]
    assert issues[0]["metisTriaged"] is True
    assert issues[0]["metisTriageStatus"] == "valid"
    assert issues[0]["metisTriageReason"] == "Concrete evidence found."
    assert issues[1]["metisTriageStatus"] == "inconclusive"


def test_save_output_json_matches_triage_annotations_by_identity(tmp_path):
    output_path = tmp_path / "results.json"
    results = {
        "reviews": [
            {
                "file": "src/a.c",
                "reviews": [
                    {"issue": "Issue A", "line_number": 10},
                    {"issue": "Issue B", "line_number": 20},
                ],
            }
        ]
    }
    # Intentionally reverse SARIF result order; mapping should still attach by identity.
    triaged_sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "message": {"text": "Issue B"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/a.c"},
                                    "region": {"startLine": 20},
                                }
                            }
                        ],
                        "properties": {
                            "metisTriaged": True,
                            "metisTriageStatus": "invalid",
                            "metisTriageReason": "Contradicted by code.",
                            "metisTriageTimestamp": "2026-01-01T00:00:02Z",
                        },
                    },
                    {
                        "message": {"text": "Issue A"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/a.c"},
                                    "region": {"startLine": 10},
                                }
                            }
                        ],
                        "properties": {
                            "metisTriaged": True,
                            "metisTriageStatus": "valid",
                            "metisTriageReason": "Concrete evidence found.",
                            "metisTriageTimestamp": "2026-01-01T00:00:03Z",
                        },
                    },
                ]
            }
        ],
    }

    save_output(str(output_path), results, quiet=True, sarif_payload=triaged_sarif)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    issues = payload["reviews"][0]["reviews"]
    assert issues[0]["issue"] == "Issue A"
    assert issues[0]["metisTriageStatus"] == "valid"
    assert issues[1]["issue"] == "Issue B"
    assert issues[1]["metisTriageStatus"] == "invalid"


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
