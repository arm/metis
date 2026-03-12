# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
import tempfile
from pathlib import Path
from typing import Any

METIS_TRIAGED_KEY = "metisTriaged"
METIS_TRIAGE_STATUS_KEY = "metisTriageStatus"
METIS_TRIAGE_REASON_KEY = "metisTriageReason"
METIS_TRIAGE_TIMESTAMP_KEY = "metisTriageTimestamp"


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
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError("SARIF payload must be a JSON object")
    if not isinstance(payload.get("runs"), list):
        raise ValueError("Invalid SARIF payload: missing runs array")
    return payload


def save_sarif_file(path: str | Path, payload: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=p.parent,
        prefix=f".{p.name}.",
        suffix=".tmp",
        delete=False,
    ) as tmp:
        json.dump(payload, tmp, indent=4)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    os.replace(tmp_path, p)


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
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result_index, result in enumerate(results):
            if not isinstance(result, dict):
                continue
            if not include_triaged and _is_already_triaged(result):
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


def _is_already_triaged(result: dict[str, Any]) -> bool:
    properties = result.get("properties")
    if not isinstance(properties, dict):
        return False
    return bool(properties.get(METIS_TRIAGED_KEY))


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
                    file_path = str(artifact.get("uri") or "")
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
) -> bool:
    runs = payload.get("runs")
    if not isinstance(runs, list) or run_index >= len(runs):
        return False
    run = runs[run_index]
    if not isinstance(run, dict):
        return False
    results = run.get("results")
    if not isinstance(results, list) or result_index >= len(results):
        return False
    result = results[result_index]
    if not isinstance(result, dict):
        return False

    properties = result.get("properties")
    if not isinstance(properties, dict):
        properties = {}
        result["properties"] = properties

    properties[METIS_TRIAGED_KEY] = True
    properties[METIS_TRIAGE_STATUS_KEY] = status
    properties[METIS_TRIAGE_REASON_KEY] = reason
    properties[METIS_TRIAGE_TIMESTAMP_KEY] = datetime.now(timezone.utc).isoformat()
    return True
