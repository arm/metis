# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from pathlib import Path
from typing import Any
from typing import Literal
from typing import get_args
from urllib.parse import unquote
from urllib.parse import urlsplit
from urllib.request import url2pathname

from metis.json_io import json_object_from_pairs
from metis.json_io import write_json_atomic

TriageDecisionSource = Literal[
    "model", "validation_failure", "execution_failure", "policy"
]
TRIAGE_DECISION_SOURCES = get_args(TriageDecisionSource)

METIS_TRIAGED_KEY = "metisTriaged"
METIS_FINDING_ID_KEY = "metisFindingId"
METIS_URI_ENCODING_KEY = "metisUriEncoding"
METIS_TRIAGE_STATUS_KEY = "metisTriageStatus"
METIS_TRIAGE_REASON_KEY = "metisTriageReason"
METIS_TRIAGE_TIMESTAMP_KEY = "metisTriageTimestamp"
METIS_TRIAGE_EVIDENCE_KEY = "metisTriageEvidence"
METIS_TRIAGE_RESOLUTION_CHAIN_KEY = "metisTriageResolutionChain"
METIS_TRIAGE_UNRESOLVED_HOPS_KEY = "metisTriageUnresolvedHops"
METIS_TRIAGE_DECISION_SOURCE_KEY = "metisTriageDecisionSource"
METIS_TRIAGE_VALIDATION_ERRORS_KEY = "metisTriageValidationErrors"
METIS_EVIDENCE_REQUIREMENTS_KEY = "metisEvidenceRequirements"
METIS_EVIDENCE_COVERAGE_KEY = "metisEvidenceCoverage"
METIS_MISSING_EVIDENCE_KEY = "metisMissingEvidence"
METIS_THREAT_MODEL_POLICY_KEY = "metisThreatModelPolicy"

TRIAGE_ANNOTATION_KEYS = frozenset(
    {
        METIS_TRIAGED_KEY,
        METIS_TRIAGE_STATUS_KEY,
        METIS_TRIAGE_REASON_KEY,
        METIS_TRIAGE_TIMESTAMP_KEY,
        METIS_TRIAGE_EVIDENCE_KEY,
        METIS_TRIAGE_RESOLUTION_CHAIN_KEY,
        METIS_TRIAGE_UNRESOLVED_HOPS_KEY,
        METIS_TRIAGE_DECISION_SOURCE_KEY,
        METIS_TRIAGE_VALIDATION_ERRORS_KEY,
        METIS_EVIDENCE_REQUIREMENTS_KEY,
        METIS_EVIDENCE_COVERAGE_KEY,
        METIS_MISSING_EVIDENCE_KEY,
        METIS_THREAT_MODEL_POLICY_KEY,
    }
)


@dataclass(frozen=True)
class SarifFinding:
    run_index: int
    result_index: int
    message: str
    rule_id: str
    file_path: str
    line: int
    snippet: str
    source_tool: str
    is_metis_source: bool
    explanation: str


def load_sarif_file(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        payload = json.load(f, object_pairs_hook=json_object_from_pairs)
    if not isinstance(payload, dict):
        raise ValueError("SARIF payload must be a JSON object")
    if not isinstance(payload.get("runs"), list):
        raise ValueError("Invalid SARIF payload: missing runs array")
    return payload


def save_sarif_file(path: str | Path, payload: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    write_json_atomic(p, payload, indent=4)


def apply_triage_annotations(report_data: Any, sarif_payload: Any) -> Any:
    if not isinstance(report_data, dict) or not isinstance(sarif_payload, dict):
        return report_data
    reviews = report_data.get("reviews")
    runs = sarif_payload.get("runs")
    if not isinstance(reviews, list) or not isinstance(runs, list):
        return report_data

    properties_by_id: dict[str, dict[str, Any]] = {}
    ambiguous_ids: set[str] = set()
    for run in runs:
        results = run.get("results") if isinstance(run, dict) else None
        if not isinstance(results, list):
            continue
        for result in results:
            properties = result.get("properties") if isinstance(result, dict) else None
            if not isinstance(properties, dict):
                continue
            finding_id = str(properties.get(METIS_FINDING_ID_KEY) or "").strip()
            if not finding_id:
                continue
            if finding_id in properties_by_id:
                ambiguous_ids.add(finding_id)
            else:
                properties_by_id[finding_id] = properties
    for finding_id in ambiguous_ids:
        properties_by_id.pop(finding_id, None)

    issues_by_id: dict[str, dict[str, Any]] = {}
    ambiguous_report_ids: set[str] = set()
    for review in reviews:
        issues = review.get("reviews") if isinstance(review, dict) else None
        if not isinstance(issues, list):
            continue
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            finding_id = str(issue.get("id") or "").strip()
            if not finding_id:
                continue
            if finding_id in issues_by_id:
                ambiguous_report_ids.add(finding_id)
            else:
                issues_by_id[finding_id] = issue
    for finding_id in ambiguous_report_ids:
        issues_by_id.pop(finding_id, None)

    for finding_id, issue in issues_by_id.items():
        properties = properties_by_id.get(finding_id)
        if properties is not None:
            _apply_triage_properties(issue, properties)
    return report_data


def extract_findings(
    payload: dict[str, Any], *, include_triaged: bool = False
) -> list[SarifFinding]:
    findings: list[SarifFinding] = []
    runs = payload.get("runs")
    if not isinstance(runs, list):
        return findings

    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            continue
        source_tool, is_metis_source = _run_source_metadata(run)
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError(f"SARIF run {run_index} results must be an array")
        for result_index, result in enumerate(results):
            if not isinstance(result, dict):
                raise ValueError(
                    f"SARIF result {run_index}:{result_index} must be an object"
                )
            if _is_already_triaged(result.get("properties")) and not include_triaged:
                continue
            findings.append(
                _to_finding(
                    run_index,
                    result_index,
                    result,
                    source_tool=source_tool,
                    is_metis_source=is_metis_source,
                )
            )
    return findings


def _is_already_triaged(properties: object) -> bool:
    if not isinstance(properties, dict):
        return False
    triaged = properties.get(METIS_TRIAGED_KEY, False)
    if not isinstance(triaged, bool):
        raise ValueError("metisTriaged must be a boolean")
    return triaged


def _to_finding(
    run_index: int,
    result_index: int,
    result: dict[str, Any],
    *,
    source_tool: str,
    is_metis_source: bool,
) -> SarifFinding:
    message_obj = result.get("message")
    message = ""
    if isinstance(message_obj, dict):
        message = str(message_obj.get("text") or "")
    elif isinstance(message_obj, str):
        message = message_obj

    rule_id = str(result.get("ruleId") or "")

    file_path = ""
    line = 1
    snippet = ""
    locations = result.get("locations")
    if isinstance(locations, list) and locations:
        first = locations[0]
        if isinstance(first, dict):
            physical = first.get("physicalLocation")
            if isinstance(physical, dict):
                artifact = physical.get("artifactLocation")
                if isinstance(artifact, dict):
                    uri = str(artifact.get("uri") or "")
                    properties = result.get("properties")
                    if is_metis_source and not (
                        isinstance(properties, dict)
                        and properties.get(METIS_URI_ENCODING_KEY) == "percent"
                    ):
                        file_path = uri
                    else:
                        try:
                            if re.search(r"%(?![0-9a-fA-F]{2})", uri):
                                raise ValueError("Invalid percent escape")
                            parsed_uri = urlsplit(uri)
                            if parsed_uri.scheme == "file" and parsed_uri.netloc in (
                                "",
                                "localhost",
                            ):
                                unquote(parsed_uri.path, errors="strict")
                                file_path = url2pathname(parsed_uri.path)
                            elif not parsed_uri.scheme and not parsed_uri.netloc:
                                file_path = unquote(uri, errors="strict")
                        except ValueError:
                            pass
                region = physical.get("region")
                if isinstance(region, dict):
                    raw_line = region.get("startLine")
                    try:
                        parsed_line = int(raw_line)
                        if parsed_line > 0:
                            line = parsed_line
                    except Exception:
                        line = 1
                    snippet_obj = region.get("snippet")
                    if isinstance(snippet_obj, dict):
                        snippet = str(snippet_obj.get("text") or "")

    explanation = _extract_explanation_text(result, is_metis_source=is_metis_source)

    return SarifFinding(
        run_index=run_index,
        result_index=result_index,
        message=message,
        rule_id=rule_id,
        file_path=file_path,
        line=line,
        snippet=snippet,
        source_tool=source_tool,
        is_metis_source=is_metis_source,
        explanation=explanation,
    )


def _run_source_metadata(run: dict[str, Any]) -> tuple[str, bool]:
    tool = run.get("tool")
    if not isinstance(tool, dict):
        return "", False
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        return "", False
    name = str(driver.get("name") or "").strip()
    full_name = str(driver.get("fullName") or "").strip()
    signature = f"{name} {full_name}".lower()
    is_metis = "metis" in signature
    return name or full_name, is_metis


def _extract_explanation_text(result: dict[str, Any], *, is_metis_source: bool) -> str:
    if not is_metis_source:
        return ""
    properties = result.get("properties")
    if not isinstance(properties, dict):
        return ""
    parts: list[str] = []
    for key in ("reasoning", "why", "mitigation"):
        value = str(properties.get(key) or "").strip()
        if value:
            parts.append(f"{key}: {value}")
    return "\n".join(parts)


def apply_triage_result(
    payload: dict[str, Any],
    *,
    run_index: int,
    result_index: int,
    status: str,
    reason: str,
    metadata: dict[str, Any] | None = None,
) -> bool:
    runs = payload.get("runs")
    if not isinstance(runs, list) or not 0 <= run_index < len(runs):
        return False
    run = runs[run_index]
    if not isinstance(run, dict):
        return False
    results = run.get("results")
    if not isinstance(results, list) or not 0 <= result_index < len(results):
        return False
    result = results[result_index]
    if not isinstance(result, dict):
        return False

    properties = result.get("properties")
    if not isinstance(properties, dict):
        properties = {}
        result["properties"] = properties

    metadata = metadata or {}
    properties[METIS_TRIAGED_KEY] = (
        metadata.get("decision_source") != "execution_failure"
    )
    properties[METIS_TRIAGE_STATUS_KEY] = status
    properties[METIS_TRIAGE_REASON_KEY] = reason
    properties[METIS_TRIAGE_TIMESTAMP_KEY] = datetime.now(timezone.utc).isoformat()
    _apply_triage_metadata(properties, metadata)
    return True


def _apply_triage_metadata(
    properties: dict[str, Any], metadata: dict[str, Any]
) -> None:
    for field, key in (
        ("evidence", METIS_TRIAGE_EVIDENCE_KEY),
        ("resolution_chain", METIS_TRIAGE_RESOLUTION_CHAIN_KEY),
        ("unresolved_hops", METIS_TRIAGE_UNRESOLVED_HOPS_KEY),
        ("validation_errors", METIS_TRIAGE_VALIDATION_ERRORS_KEY),
    ):
        value = metadata.get(field)
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            properties[key] = list(value)
        else:
            properties.pop(key, None)
    decision_source = metadata.get("decision_source")
    if isinstance(decision_source, str) and decision_source in TRIAGE_DECISION_SOURCES:
        properties[METIS_TRIAGE_DECISION_SOURCE_KEY] = decision_source
    else:
        properties.pop(METIS_TRIAGE_DECISION_SOURCE_KEY, None)

    evidence_requirements = metadata.get("evidence_requirements")
    if isinstance(evidence_requirements, list):
        properties[METIS_EVIDENCE_REQUIREMENTS_KEY] = [
            str(item) for item in evidence_requirements if str(item or "").strip()
        ]
    else:
        properties.pop(METIS_EVIDENCE_REQUIREMENTS_KEY, None)

    evidence_coverage = metadata.get("evidence_coverage")
    if isinstance(evidence_coverage, dict):
        properties[METIS_EVIDENCE_COVERAGE_KEY] = dict(evidence_coverage)
    else:
        properties.pop(METIS_EVIDENCE_COVERAGE_KEY, None)

    missing_evidence = metadata.get("missing_evidence")
    if isinstance(missing_evidence, list):
        properties[METIS_MISSING_EVIDENCE_KEY] = [
            str(item) for item in missing_evidence if str(item or "").strip()
        ]
    else:
        properties.pop(METIS_MISSING_EVIDENCE_KEY, None)

    threat_model_policy = metadata.get("threat_model_policy")
    if isinstance(threat_model_policy, dict):
        properties[METIS_THREAT_MODEL_POLICY_KEY] = dict(threat_model_policy)
    else:
        properties.pop(METIS_THREAT_MODEL_POLICY_KEY, None)


def _apply_triage_properties(issue: dict[str, Any], properties: dict[str, Any]) -> None:
    if METIS_TRIAGED_KEY in properties:
        issue[METIS_TRIAGED_KEY] = _is_already_triaged(properties)
    text_keys = (
        METIS_TRIAGE_STATUS_KEY,
        METIS_TRIAGE_REASON_KEY,
        METIS_TRIAGE_TIMESTAMP_KEY,
    )
    for key in sorted(TRIAGE_ANNOTATION_KEYS - {METIS_TRIAGED_KEY}):
        if key in properties:
            issue[key] = (
                str(properties[key] or "")
                if key in text_keys
                else deepcopy(properties[key])
            )
        elif key not in text_keys:
            issue.pop(key, None)
