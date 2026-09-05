# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import csv
import html
import json
import re
from collections import Counter
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import Iterable, Tuple

from metis.json_io import atomic_text_writer
from metis.json_io import write_json_atomic
from metis.sarif.triage import extract_findings
from metis.sarif.writer import generate_sarif


def export_html(
    report_data, output_path: Path, template: str, metis_version: str
) -> Path:
    """Render the HTML report template with the provided data."""
    issues = _flatten_issues(report_data)
    document = _build_html_document(issues, output_path.name, template, metis_version)
    html_path = output_path
    html_path.parent.mkdir(parents=True, exist_ok=True)
    with atomic_text_writer(html_path) as handle:
        handle.write(document)
    return html_path


def export_sarif(
    report_data, output_path: Path, sarif_payload=None
) -> Tuple[Path, dict]:
    """Generate SARIF payload (or reuse) and persist it to disk."""
    payload = (
        sarif_payload if sarif_payload is not None else generate_sarif(report_data)
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_json_atomic(output_path, payload, indent=4)
    return output_path, payload


def export_csv(report_data, output_path: Path) -> Path:
    """Write flattened issues to a CSV file."""
    issues = _flatten_issues(report_data)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with atomic_text_writer(output_path, newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(
            [
                "File",
                "Line",
                "Severity",
                "CWE",
                "Issue",
                "Reasoning",
                "Mitigation",
                "Confidence",
            ]
        )
        for issue in issues:
            writer.writerow(
                [
                    issue.get("file", ""),
                    issue.get("line", ""),
                    issue.get("severity", ""),
                    issue.get("cwe", ""),
                    issue.get("issue", ""),
                    issue.get("reasoning", ""),
                    issue.get("mitigation", ""),
                    issue.get("confidence", ""),
                ]
            )
    return output_path


def _build_html_document(
    issues: Iterable[dict], source_name: str, template: str, metis_version: str
) -> str:
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    display_name = Path(source_name).stem if source_name else source_name
    title = f"Metis Security Report - {display_name}"

    severity_counts = Counter()
    cwe_counts = Counter()
    severity_priority = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Unknown": 0,
    }
    file_stats: dict[str, dict[str, object]] = {}
    folder_stats: dict[str, dict[str, object]] = {}

    for issue in issues:
        severity = issue.get("severity") or "Unknown"
        cwe = issue.get("cwe") or "CWE-Unknown"
        severity_counts[severity] += 1
        cwe_counts[cwe] += 1

        file_name = issue.get("file", "Unknown") or "Unknown"
        folder = file_name.split("/", 1)[0] if "/" in file_name else file_name
        file_entry = file_stats.setdefault(
            file_name,
            {
                "count": 0,
                "maxSeverity": "Unknown",
                "severityCounts": Counter(),
            },
        )
        file_entry["count"] = int(file_entry["count"]) + 1
        file_entry["severityCounts"][severity] += 1
        current_priority = severity_priority.get(file_entry["maxSeverity"], 0)
        candidate_priority = severity_priority.get(severity, 0)
        if candidate_priority > current_priority:
            file_entry["maxSeverity"] = severity

        folder_entry = folder_stats.setdefault(
            folder,
            {
                "count": 0,
                "severityCounts": Counter(),
            },
        )
        folder_entry["count"] = int(folder_entry["count"]) + 1
        folder_entry["severityCounts"][severity] += 1

    file_stats_serialized = {
        file_name: {
            "count": details["count"],
            "severityCounts": dict(details["severityCounts"]),
            "maxSeverity": details["maxSeverity"],
        }
        for file_name, details in file_stats.items()
    }

    folder_stats_serialized = {
        folder_name: {
            "count": details["count"],
            "severityCounts": dict(details["severityCounts"]),
        }
        for folder_name, details in folder_stats.items()
    }

    payload = {
        "issues": list(issues),
        "severityCounts": dict(severity_counts),
        "cweCounts": dict(cwe_counts),
        "fileStats": file_stats_serialized,
        "folderStats": folder_stats_serialized,
    }
    data_json = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    substitutions = {
        "__TITLE__": html.escape(title),
        "__GENERATED_AT__": html.escape(generated_at),
        "__DATA_JSON__": data_json,
        "__METIS_VERSION__": html.escape(metis_version),
    }
    return re.sub(
        "|".join(substitutions), lambda match: substitutions[match[0]], template
    )


def _flatten_issues(report_data) -> list[dict]:
    issues = []
    if not isinstance(report_data, dict):
        return issues

    reviews = report_data.get("reviews", [])
    if "reviews" not in report_data:
        for finding in extract_findings(report_data, include_triaged=True):
            result = report_data["runs"][finding.run_index]["results"][
                finding.result_index
            ]
            properties = result.get("properties")
            reviews.append(
                {
                    "file": finding.file_path,
                    "reviews": [
                        {
                            **(properties if isinstance(properties, dict) else {}),
                            "issue": finding.message,
                            "line_number": finding.line,
                            "code_snippet": finding.snippet,
                        }
                    ],
                }
            )
    for file_entry in reviews:
        file_name = file_entry.get("file") or file_entry.get("file_path") or "Unknown"
        try:
            file_name = str(file_name)
        except Exception:  # pragma: no cover - defensive
            file_name = "Unknown"

        for issue in file_entry.get("reviews", []):
            severity = issue.get("severity") or "Unknown"
            if isinstance(severity, str):
                severity = severity.strip() or "Unknown"
            else:
                severity = str(severity)
            if severity.lower() in {"critical", "high", "medium", "low", "unknown"}:
                severity = severity.capitalize()

            cwe = issue.get("cwe") or "CWE-Unknown"
            if isinstance(cwe, (list, tuple)):
                cwe = ", ".join(str(item) for item in cwe if item)
            else:
                cwe = str(cwe)

            cwe_match = re.search(r"(\d+)", cwe)
            cwe_link = (
                f"https://cwe.mitre.org/data/definitions/{cwe_match.group(1)}.html"
                if cwe_match
                else ""
            )

            folder = file_name.split("/", 1)[0] if "/" in file_name else file_name
            issues.append(
                {
                    "file": file_name,
                    "line": str(issue.get("line_number") or ""),
                    "severity": severity,
                    "cwe": cwe,
                    "cweLink": cwe_link,
                    "issue": _coerce_to_string(issue.get("issue")),
                    "reasoning": _coerce_to_string(issue.get("reasoning")),
                    "mitigation": _coerce_to_string(issue.get("mitigation")),
                    "confidence": _coerce_to_string(issue.get("confidence")),
                    "snippet": _coerce_to_string(issue.get("code_snippet")),
                    "triageStatus": _coerce_to_string(issue.get("metisTriageStatus")),
                    "triageReason": _coerce_to_string(issue.get("metisTriageReason")),
                    "triageTimestamp": _coerce_to_string(
                        issue.get("metisTriageTimestamp")
                    ),
                    "folder": folder,
                }
            )

    return issues


def _coerce_to_string(value):
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:  # pragma: no cover - defensive
        return ""
