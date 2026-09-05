# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy
import csv
import json

import pytest

from metis.cli.exporters import export_csv
from metis.cli.exporters import export_html
from metis.sarif.triage import apply_triage_annotations
from metis.sarif.triage import apply_triage_result
from metis.sarif.writer import generate_sarif


def test_sarif_roundtrip_exports_preserve_review_fields_and_triage_status(tmp_path):
    statuses = ("valid", "invalid", "inconclusive", None)
    review = {
        "reviews": [
            {
                "file": "audit.txt",
                "reviews": [
                    {
                        "id": f"marker-{index}",
                        "issue": f"Format marker {index}",
                        "line_number": index + 1,
                        "code_snippet": "audit marker",
                        "severity": "Medium",
                        "cwe": "CWE-Unknown",
                        "reasoning": "Format check",
                        "mitigation": "Keep the marker",
                        "confidence": 0.5,
                    }
                    for index in range(len(statuses))
                ],
            }
        ]
    }
    sarif = generate_sarif(review)
    for index, status in enumerate(statuses):
        if status is not None:
            assert apply_triage_result(
                sarif,
                run_index=0,
                result_index=index,
                status=status,
                reason=f"Recorded {status}",
            )
    apply_triage_annotations(review, sarif)
    original_sarif = deepcopy(sarif)

    review_html = export_html(review, tmp_path / "review.html", "__DATA_JSON__", "test")
    sarif_html = export_html(sarif, tmp_path / "sarif.html", "__DATA_JSON__", "test")
    review_data = json.loads(review_html.read_text())
    sarif_data = json.loads(sarif_html.read_text())
    assert sarif_data == review_data
    assert [item["triageStatus"] for item in sarif_data["issues"]] == [
        "valid",
        "invalid",
        "inconclusive",
        "",
    ]
    assert [item["triageReason"] for item in sarif_data["issues"]] == [
        "Recorded valid",
        "Recorded invalid",
        "Recorded inconclusive",
        "",
    ]
    assert all(item["triageTimestamp"] for item in sarif_data["issues"][:3])
    assert sarif_data["severityCounts"] == {"Medium": 4}

    review_csv = export_csv(review, tmp_path / "review.csv")
    sarif_csv = export_csv(sarif, tmp_path / "sarif.csv")
    assert sarif_csv.read_text() == review_csv.read_text()
    with sarif_csv.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert [row["Issue"] for row in rows] == [f"Format marker {i}" for i in range(4)]
    assert sarif == original_sarif


def test_external_sarif_exports_without_metis_properties(tmp_path):
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "message": {"text": "External format marker"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "external.txt"},
                                    "region": {
                                        "startLine": 7,
                                        "snippet": {"text": "external marker"},
                                    },
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }
    html_path = export_html(sarif, tmp_path / "external.html", "__DATA_JSON__", "test")
    issues = json.loads(html_path.read_text())["issues"]
    assert len(issues) == 1
    assert issues[0]["issue"] == "External format marker"
    assert issues[0]["file"] == "external.txt"
    assert issues[0]["line"] == "7"
    assert issues[0]["snippet"] == "external marker"
    assert issues[0]["triageStatus"] == ""
    csv_path = export_csv(sarif, tmp_path / "external.csv")
    with csv_path.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 1
    assert rows[0]["Issue"] == "External format marker"
    assert rows[0]["File"] == "external.txt"
    assert rows[0]["Line"] == "7"


@pytest.mark.parametrize(
    "payload",
    (
        {},
        {"reviews": []},
        {"version": "2.1.0", "runs": []},
        {"version": "2.1.0", "runs": [{"results": []}]},
    ),
)
def test_empty_payload_exports_remain_empty(tmp_path, payload):
    html_path = export_html(payload, tmp_path / "empty.html", "__DATA_JSON__", "test")
    assert json.loads(html_path.read_text())["issues"] == []
    csv_path = export_csv(payload, tmp_path / "empty.csv")
    with csv_path.open(newline="") as stream:
        assert list(csv.DictReader(stream)) == []


def test_html_template_keeps_placeholder_text_in_report_and_metadata(tmp_path):
    text = "__TITLE__ __GENERATED_AT__ __DATA_JSON__ __METIS_VERSION__"
    report = {"reviews": [{"reviews": [{"issue": text}]}]}
    template = "__TITLE__\n__GENERATED_AT__\n__METIS_VERSION__\n__DATA_JSON__"
    html_path = export_html(
        report,
        tmp_path / "__DATA_JSON__ & <note>.html",
        template,
        "release-__TITLE__",
    )
    title, generated_at, version, data = html_path.read_text().split("\n", 3)
    assert title == "Metis Security Report - __DATA_JSON__ &amp; &lt;note&gt;"
    assert generated_at.endswith(" UTC")
    assert version == "release-__TITLE__"
    assert json.loads(data)["issues"][0]["issue"] == text
    csv_path = export_csv(report, tmp_path / "report.csv")
    with csv_path.open(newline="") as stream:
        assert next(csv.DictReader(stream))["Issue"] == text


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("high", "High"),
        ("HIGH", "High"),
        (" critical ", "Critical"),
        ("medium", "Medium"),
        ("LOW", "Low"),
        ("unknown", "Unknown"),
        ("CustomCase", "CustomCase"),
    ],
)
def test_exports_normalize_known_severity_names(tmp_path, severity, expected):
    report = {
        "reviews": [
            {
                "file": "audit.txt",
                "reviews": [{"issue": "Format marker", "severity": severity}],
            }
        ]
    }
    html_path = export_html(report, tmp_path / "report.html", "__DATA_JSON__", "test")
    data = json.loads(html_path.read_text())
    assert data["issues"][0]["severity"] == expected
    assert data["severityCounts"] == {expected: 1}
    assert data["fileStats"]["audit.txt"]["maxSeverity"] == (
        "Unknown" if expected == "CustomCase" else expected
    )
    csv_path = export_csv(report, tmp_path / "report.csv")
    with csv_path.open(newline="") as stream:
        assert next(csv.DictReader(stream))["Severity"] == expected
