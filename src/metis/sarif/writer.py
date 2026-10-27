# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from uuid import uuid4
from uuid import uuid5
from copy import deepcopy
from contextlib import contextmanager
from urllib.parse import quote

from metis.json_io import sorted_json_records
from metis.sarif.triage import METIS_FINDING_ID_KEY
from metis.sarif.triage import METIS_URI_ENCODING_KEY
from metis.sarif.triage import _apply_triage_properties
from metis.version import __version__ as TOOL_VERSION
from metis.sarif.utils import anchor_fingerprint, create_fingerprint, read_file_lines

DEFAULT_CONTEXT_LINES = 3
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


@contextmanager
def normalize_finding_ids(
    records, *, directory, check_cancelled=lambda: None, id_namespace=None
):
    """Normalize IDs on disk, preserving first originals over generated IDs.

    A later original ID can displace a generated ID. An unchanged input and
    supplied namespace produce the same repairs across checkpoints.
    """
    sorter = None

    def sort(entries, key):
        nonlocal sorter
        previous = sorter
        sorter = sorted_json_records(
            entries, key=key, directory=directory, check_cancelled=check_cancelled
        )
        try:
            return sorter.__enter__()
        finally:
            if previous is not None:
                previous.__exit__(None, None, None)

    try:
        by_id = sort(
            records,
            key=lambda record: (
                str(record.get("id") or "").strip(),
                record["position"],
            ),
        )
        repaired = False

        def normalized():
            nonlocal repaired
            previous = None
            for record in by_id:
                original = str(record.get("id") or "").strip()
                record["id"] = original
                attempt = -1
                if not original or original == previous:
                    repaired = True
                    attempt = 0
                    record["id"] = (
                        uuid5(id_namespace, str(record["position"]))
                        if id_namespace is not None
                        else uuid4()
                    ).hex
                previous = original
                yield {"record": record, "attempt": attempt}

        ordered = sort(normalized(), key=lambda entry: entry["record"]["position"])

        def unique_positions(entries):
            previous = None
            for entry in entries:
                position = entry["record"]["position"]
                if position == previous:
                    raise ValueError("Duplicate finding position")
                previous = position
                yield entry

        ordered = unique_positions(ordered)

        def repair_collisions():
            nonlocal repaired
            previous = None
            for entry in by_id:
                record = entry["record"]
                original = record["id"]
                if original == previous:
                    repaired = True
                    entry["attempt"] += 1
                    record["id"] = (
                        uuid5(
                            id_namespace,
                            f"{record['position']}:{entry['attempt']}",
                        )
                        if id_namespace is not None
                        else uuid4()
                    ).hex
                previous = original
                yield entry

        collision_passes = 0
        while repaired:
            if collision_passes == 8:
                raise ValueError("Finding ID collision limit exceeded")
            collision_passes += 1
            repaired = False
            by_id = sort(
                ordered,
                key=lambda entry: (
                    entry["record"]["id"],
                    entry["attempt"] >= 0,
                    entry["record"]["position"],
                ),
            )
            ordered = sort(
                repair_collisions(), key=lambda entry: entry["record"]["position"]
            )
        yield (entry["record"] for entry in ordered)
    finally:
        if sorter is not None:
            sorter.__exit__(None, None, None)


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
    *,
    read_source: bool = True,
):
    """
    Generate a SARIF (Static Analysis Results Interchange Format) report.

    Args:
        results: A dict containing AI review results, expected to have a "reviews" list.
        tool_name: Name of the tool producing the report.
        automation_id: Identifier for the automation run.
        context_lines: Number of lines of context to include around each issue.
        read_source: Whether to read source files for snippets and context.

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
                        "rules": deepcopy(RULES),
                    }
                },
                "automationDetails": {"id": automation_id},
                "results": [],
            }
        ],
    }

    sarif["runs"][0]["results"] = list(
        iter_sarif_results(
            results.get("reviews", []), context_lines, read_source=read_source
        )
    )
    return sarif


def iter_sarif_results(
    reviews,
    context_lines=DEFAULT_CONTEXT_LINES,
    *,
    read_source: bool = True,
    normalize_ids: bool = True,
):
    """Map review groups lazily, reading each group's source file once.

    Disable ID normalization only when the caller already ensures globally unique,
    nonempty, trimmed string IDs. That path retains no collection of finding IDs.
    """

    finding_ids: set[str] | None = set() if normalize_ids else None
    for review in reviews:
        file_path = review.get("file_path")
        artifact_uri = review.get("file") or file_path or "<unknown>"
        lines = read_file_lines(file_path) if read_source and file_path else []
        source_available = bool(lines) and lines != ["<source unavailable>"]
        total_lines = len(lines) if source_available else 0

        for issue in review.get("reviews", []):
            if finding_ids is None:
                finding_id = issue.get("id")
                if (
                    not isinstance(finding_id, str)
                    or not finding_id
                    or finding_id != finding_id.strip()
                ):
                    raise ValueError(
                        "Pre-normalized finding IDs must be nonempty trimmed strings"
                    )
            else:
                finding_id = str(issue.get("id") or "").strip()
                if not finding_id or finding_id in finding_ids:
                    finding_id = uuid4().hex
                issue["id"] = finding_id
                finding_ids.add(finding_id)
            text = issue.get("issue", "unspecified")
            anchor = (
                issue.get("anchor") if isinstance(issue.get("anchor"), dict) else None
            )
            anchor_start = anchor_end = 0
            anchor_fp = None
            if anchor:
                try:
                    anchor_start = int(anchor["start_line"])
                    anchor_end = int(anchor["end_line"])
                    if anchor_start < 0 or anchor_end < anchor_start:
                        raise ValueError("Invalid anchor line range")
                    anchor_fp = anchor_fingerprint(anchor)
                except (KeyError, TypeError, ValueError, OverflowError):
                    anchor = None
                    anchor_start = anchor_end = 0
            reported_line_num = _normalise_line_number(
                anchor_start or issue.get("line_number", 1)
            )
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

            properties = {
                METIS_FINDING_ID_KEY: finding_id,
                METIS_URI_ENCODING_KEY: "percent",
            }
            _apply_triage_properties(properties, issue)
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

            if anchor:
                properties["anchor"] = anchor

            region_end_line = (
                min(anchor_end, total_lines)
                if (anchor_end and total_lines)
                else anchor_end
            ) or (line_num + snippet_line_count - 1)

            partial_fingerprints = {"primaryLocationLineHash": fingerprint}
            if anchor_fp:
                partial_fingerprints["metisAnchor/v1"] = anchor_fp

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
                            "artifactLocation": {"uri": quote(artifact_uri)},
                            "region": {
                                "startLine": line_num,
                                "endLine": max(line_num, region_end_line),
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
                "partialFingerprints": partial_fingerprints,
            }

            if properties:
                result_entry["properties"] = properties

            yield result_entry
