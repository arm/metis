# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace

import json

from metis.cli.commands import _build_triaged_sarif_payload, run_triage
from metis.cli.utils import save_output
from metis.sarif.utils import create_fingerprint


def test_build_triaged_sarif_payload_reuses_engine_path():
    class _DummyEngine:
        def __init__(self):
            self.called = False

        def triage_sarif_payload(self, payload, **kwargs):
            self.called = True
            assert kwargs.get("include_triaged") is False
            payload["runs"] = []
            return payload

    engine = _DummyEngine()
    args = SimpleNamespace(triage=True, quiet=True, include_triaged=False)
    results = {"reviews": []}

    payload = _build_triaged_sarif_payload(engine, results, args)
    assert engine.called is True
    assert isinstance(payload, dict)
    assert payload["runs"] == []


def test_run_triage_defaults_to_inplace(tmp_path):
    sarif_path = tmp_path / "input.sarif"
    sarif_path.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")

    class _DummyEngine:
        def triage_sarif_file(self, input_path, output_path=None, **kwargs):
            assert input_path == str(sarif_path)
            assert output_path is None
            assert kwargs.get("include_triaged") is False
            return input_path

    args = SimpleNamespace(quiet=True, output_file=None, include_triaged=False)
    run_triage(_DummyEngine(), str(sarif_path), args)


def test_run_triage_uses_sarif_output_target(tmp_path):
    sarif_path = tmp_path / "input.sarif"
    expected_output_path = tmp_path / "output.sarif"
    sarif_path.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")

    class _DummyEngine:
        def triage_sarif_file(self, input_path, output_path=None, **kwargs):
            assert input_path == str(sarif_path)
            assert output_path == str(expected_output_path)
            assert kwargs.get("include_triaged") is True
            return output_path

    args = SimpleNamespace(
        quiet=True,
        output_file=[str(expected_output_path), "x.json"],
        include_triaged=True,
    )
    run_triage(_DummyEngine(), str(sarif_path), args)


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
