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
        artifact_uri = review.get("file", "<unknown>")
        lines = read_file_lines(file_path) if file_path else []
        total_lines = len(lines)

        for issue in review.get("reviews", []):
            text = issue.get("issue", "unspecified")
            raw_line = issue.get("line_number", 1)
            line_num = max(1, min(raw_line, total_lines or 1))

            fingerprint = create_fingerprint(
                file_path or artifact_uri, line_num, RULES[0]["id"]
            )

            # Calculate context window
            start = max(1, line_num - context_lines)
            end = min(line_num + context_lines, total_lines)
            block = lines[start - 1 : end]

            # Extract snippet and full context
            idx = line_num - start
            snippet = (
                block[idx].strip() if 0 <= idx < len(block) else "<source unavailable>"
            )
            context = "".join(block).strip() or "<context unavailable>"

            # Append result entry
            properties = {}
            cwe_id = issue.get("cwe")
            if isinstance(cwe_id, str) and cwe_id.strip():
                properties["cwe"] = cwe_id.strip()

            severity = issue.get("severity")
            if isinstance(severity, str) and severity.strip():
                properties["severity"] = severity.strip()

            run["results"].append(
                {
                    "ruleId": RULES[0]["id"],
                    "level": RULES[0]["defaultConfiguration"]["level"],
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
                                    "startLine": start,
                                    "snippet": {"text": snippet},
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
                    "properties": properties if properties else None,
                }
            )

    return sarif
