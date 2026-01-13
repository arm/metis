# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.version import __version__ as TOOL_VERSION
from metis.sarif.utils import read_file_lines, create_fingerprint


DEFAULT_CONTEXT_LINES = 3
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

RULES = [
    {
        "id": "AI001",
        "name": "AiSecurityRisk",
        "helpUri": "https://raw.githubusercontent.com/arm/metis/main/docs/rules/AI001.md",
        "shortDescription": {
            "text": "AI-identified security vulnerability",
            "markdown": "AI-identified security vulnerability",
        },
        "fullDescription": {
            "text": (
                "This rule indicates a security issue detected by an AI system."
                " These insights are heuristic in nature and should be reviewed by a developer."
            ),
            "markdown": (
                "This rule indicates a security issue detected by an AI system."
                " These insights are heuristic in nature and should be reviewed by a developer."
            ),
        },
        "defaultConfiguration": {"level": "warning"},
        "help": {
            "text": (
                "Provides an overview of the security issue found by the AI system"
                " and a proposed mitigation."
            ),
            "markdown": (
                "Provides an overview of the security issue found by the AI system"
                " and a proposed mitigation."
            ),
        },
    }
]


def _normalise_line_number(raw_line):
    try:
        value = int(raw_line)
        return value if value > 0 else 1
    except Exception:
        return 1


def _severity_to_level(severity: str | None) -> str:
    if not severity or not isinstance(severity, str):
        return RULES[0]["defaultConfiguration"]["level"]

    lowered = severity.strip().lower()
    if lowered in {"critical", "high"}:
        return "error"
    if lowered == "medium":
        return "warning"
    if lowered == "low":
        return "note"

    return RULES[0]["defaultConfiguration"]["level"]


def generate_sarif(
    results,
    tool_name="Metis",
    automation_id="metis-run-1",
    context_lines=DEFAULT_CONTEXT_LINES,
):
    """
    Generate a SARIF (Static Analysis Results Interchange Format) report.

    Args:
        results: A dict containing AI review results, expected to have a "reviews" list.
        tool_name: Name of the tool producing the report.
        automation_id: Identifier for the automation run.
        context_lines: Number of lines of context to include around each issue.

    Returns:
        A dict representing the SARIF JSON structure.
    """

    # Base SARIF structure
    sarif = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": TOOL_VERSION,
                        "fullName": f"{tool_name} v{TOOL_VERSION}",
                        "informationUri": "https://github.com/arm/metis",
                        "rules": RULES,
                    }
                },
                "automationDetails": {"id": automation_id},
                "results": [],
            }
        ],
    }

    run = sarif["runs"][0]

    for review in results.get("reviews", []):
        file_path = review.get("file_path")
        artifact_uri = review.get("file") or file_path or "<unknown>"
        lines = read_file_lines(file_path) if file_path else []
        source_available = bool(lines) and lines != ["<source unavailable>"]
        total_lines = len(lines) if source_available else 0

        for issue in review.get("reviews", []):
            text = issue.get("issue", "unspecified")
            reported_line_num = _normalise_line_number(issue.get("line_number", 1))
            snippet_override = issue.get("code_snippet")

            # Keep location inside the file if source is available, but remember what was reported
            if source_available and total_lines:
                line_num = min(reported_line_num, total_lines)
            else:
                line_num = reported_line_num

            fingerprint = create_fingerprint(
                file_path or artifact_uri, line_num, RULES[0]["id"]
            )

            # Prefer model-provided snippet; fall back to file content if available
            if snippet_override:
                snippet_text = str(snippet_override).strip("\n")
            elif source_available and 1 <= line_num <= total_lines:
                snippet_text = lines[line_num - 1].rstrip("\n")
            else:
                snippet_text = "<source unavailable>"

            snippet_line_count = (
                snippet_text.count("\n") + 1
                if snippet_text != "<source unavailable>"
                else 1
            )

            if source_available and 1 <= line_num <= total_lines:
                start = max(1, line_num - context_lines)
                end = min(total_lines, line_num + context_lines)
                context = (
                    "".join(lines[start - 1 : end]).rstrip("\n")
                    or "<context unavailable>"
                )
            else:
                start = line_num
                end = line_num + snippet_line_count - 1
                context = snippet_text or "<context unavailable>"

            properties = {}
            cwe_id = issue.get("cwe")
            if isinstance(cwe_id, str) and cwe_id.strip():
                properties["cwe"] = cwe_id.strip()

            severity = issue.get("severity")
            if isinstance(severity, str) and severity.strip():
                properties["severity"] = severity.strip()

            reasoning = issue.get("reasoning")
            if reasoning:
                properties["reasoning"] = str(reasoning)

            why = issue.get("why")
            if why:
                properties["why"] = str(why)

            mitigation = issue.get("mitigation")
            if mitigation:
                properties["mitigation"] = str(mitigation)

            confidence = issue.get("confidence")
            if confidence is not None:
                properties["confidence"] = confidence

            if reported_line_num != line_num:
                properties["reportedLineNumber"] = reported_line_num

            result_entry = {
                "ruleId": RULES[0]["id"],
                "level": _severity_to_level(severity),
                "message": {
                    "id": RULES[0]["id"],
                    "arguments": [text],
                    "text": text,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri},
                            "region": {
                                "startLine": line_num,
                                "endLine": line_num + snippet_line_count - 1,
                                "snippet": {"text": snippet_text},
                            },
                            "contextRegion": {
                                "startLine": start,
                                "endLine": end,
                                "snippet": {"text": context},
                            },
                        }
                    }
                ],
                "partialFingerprints": {"primaryLocationLineHash": fingerprint},
            }

            if properties:
                result_entry["properties"] = properties

            run["results"].append(result_entry)

    return sarif
