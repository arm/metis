# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from typing import TypeGuard

from metis.json_io import atomic_text_writer
from metis.json_io import load_json_object_file
from metis.json_io import parse_json_object
from metis.json_io import validate_json_tree
from metis.sarif.triage import METIS_EVIDENCE_COVERAGE_KEY
from metis.sarif.triage import METIS_EVIDENCE_REQUIREMENTS_KEY
from metis.sarif.triage import METIS_FINDING_ID_KEY
from metis.sarif.triage import METIS_MISSING_EVIDENCE_KEY
from metis.sarif.triage import METIS_THREAT_MODEL_POLICY_KEY
from metis.sarif.triage import METIS_TRIAGED_KEY
from metis.sarif.triage import METIS_TRIAGE_DECISION_SOURCE_KEY
from metis.sarif.triage import METIS_TRIAGE_EVIDENCE_KEY
from metis.sarif.triage import METIS_TRIAGE_REASON_KEY
from metis.sarif.triage import METIS_TRIAGE_RESOLUTION_CHAIN_KEY
from metis.sarif.triage import METIS_TRIAGE_STATUS_KEY
from metis.sarif.triage import METIS_TRIAGE_TIMESTAMP_KEY
from metis.sarif.triage import METIS_TRIAGE_UNRESOLVED_HOPS_KEY
from metis.sarif.triage import METIS_TRIAGE_VALIDATION_ERRORS_KEY
from metis.sarif.triage import TRIAGE_DECISION_SOURCES
from metis.sarif.writer import SARIF_VERSION


def parse_metis_sarif(data: bytes) -> dict[str, Any]:
    """Parse and validate one UTF-8 SARIF document."""
    payload = parse_json_object(data)
    validate_metis_sarif(payload)
    return payload


def load_metis_sarif_file(path: str | Path) -> dict[str, Any]:
    """Load and validate Metis SARIF."""
    payload = load_json_object_file(path)
    validate_metis_sarif(payload)
    return payload


def save_metis_sarif_file(path: str | Path, payload: dict[str, Any]) -> None:
    """Validate and atomically publish compact UTF-8 SARIF."""
    validate_metis_sarif(payload)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    encoder = json.JSONEncoder(
        ensure_ascii=False, allow_nan=False, separators=(",", ":")
    )
    with atomic_text_writer(target, mode=0o600) as stream:
        for chunk in encoder.iterencode(payload):
            stream.write(chunk)


def validate_metis_sarif(payload: dict[str, Any]) -> None:
    """Validate Metis SARIF structure."""
    if not isinstance(payload, dict):
        raise ValueError("SARIF payload must be a JSON object")
    validate_json_tree(payload)

    if payload.get("version") != SARIF_VERSION:
        raise ValueError(f"Metis SARIF must use version {SARIF_VERSION}")
    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise ValueError("Metis SARIF must contain a runs array")
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValueError(f"Metis SARIF run {run_index} must be an object")
        _validate_run(run, run_index)


def _validate_run(run: dict[str, Any], run_index: int) -> None:
    tool = run.get("tool")
    if not isinstance(tool, dict):
        raise ValueError(f"Metis SARIF run {run_index} missing tool object")
    driver = tool.get("driver")
    if not isinstance(driver, dict) or not _nonempty_string(driver.get("name")):
        raise ValueError(f"Metis SARIF run {run_index} missing tool.driver.name")
    rules = driver.get("rules")
    if "rules" in driver:
        if not isinstance(rules, list):
            raise ValueError(f"Metis SARIF run {run_index} rules must be an array")
        for rule_index, rule in enumerate(rules):
            if not isinstance(rule, dict) or not _nonempty_string(rule.get("id")):
                raise ValueError(
                    f"Metis SARIF rule {run_index}:{rule_index} missing id"
                )
    results = run.get("results")
    if not isinstance(results, list):
        raise ValueError(f"Metis SARIF run {run_index} missing results array")
    for result_index, result in enumerate(results):
        _validate_result(result, run_index, result_index)


def _validate_result(
    result: Any,
    run_index: int,
    result_index: int,
) -> None:
    prefix = f"Metis SARIF result {run_index}:{result_index}"
    if not isinstance(result, dict):
        raise ValueError(f"{prefix} must be an object")
    if not _nonempty_string(result.get("ruleId")):
        raise ValueError(f"{prefix} missing ruleId")
    message = result.get("message")
    if not isinstance(message, dict) or not _nonempty_string(message.get("text")):
        raise ValueError(f"{prefix} missing message.text")
    level = result.get("level")
    if "level" in result and not isinstance(level, str):
        raise ValueError(f"{prefix} level must be a string")
    properties = result.get("properties")
    if "properties" in result:
        if not isinstance(properties, dict):
            raise ValueError(f"{prefix} properties must be an object")
        _validate_triage_properties(properties, prefix)
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        raise ValueError(f"{prefix} missing locations")
    for location_index, location in enumerate(locations):
        _validate_location(location, prefix, location_index)


def _validate_location(
    location: Any,
    prefix: str,
    location_index: int,
) -> None:
    if not isinstance(location, dict):
        raise ValueError(f"{prefix} location {location_index} must be an object")
    primary = location_index == 0
    logical = location.get("logicalLocations")
    if "logicalLocations" in location and (
        not isinstance(logical, list)
        or any(not isinstance(item, dict) for item in logical)
    ):
        raise ValueError(f"{prefix} logicalLocations must be an array of objects")
    physical = location.get("physicalLocation")
    if not primary and "physicalLocation" not in location and logical:
        return
    if not isinstance(physical, dict):
        raise ValueError(f"{prefix} location {location_index} missing physicalLocation")
    artifact = physical.get("artifactLocation")
    address = physical.get("address")
    if "address" in physical and not isinstance(address, dict):
        raise ValueError(f"{prefix} address must be an object")
    if "artifactLocation" in physical and not isinstance(artifact, dict):
        raise ValueError(f"{prefix} artifactLocation must be an object")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    if (
        primary or isinstance(artifact, dict) and "uri" in artifact
    ) and not _nonempty_string(uri):
        raise ValueError(f"{prefix} missing artifactLocation.uri")
    if artifact is None and address is None:
        raise ValueError(f"{prefix} missing artifactLocation or address")
    region = physical.get("region")
    if primary or "region" in physical:
        if not isinstance(region, dict):
            raise ValueError(f"{prefix} missing region")
        _validate_region(region, f"{prefix} region", require_start_line=primary)
    context_region = physical.get("contextRegion")
    if "contextRegion" in physical:
        if region is None:
            raise ValueError(f"{prefix} contextRegion requires region")
        if not isinstance(context_region, dict):
            raise ValueError(f"{prefix} contextRegion must be an object")
        _validate_region(context_region, f"{prefix} contextRegion")


def _validate_region(
    region: dict[str, Any], prefix: str, *, require_start_line: bool = False
) -> None:
    start = region.get("startLine")
    if require_start_line or "startLine" in region:
        if type(start) is not int:
            raise ValueError(f"{prefix}.startLine must be an integer")
        if not 1 <= start <= 2_147_483_647:
            raise ValueError(f"{prefix}.startLine must be positive")
    end = region.get("endLine")
    if "endLine" in region:
        if type(end) is not int:
            raise ValueError(f"{prefix}.endLine must be an integer")
        if not (start or 1) <= end <= 2_147_483_647:
            raise ValueError(f"{prefix}.endLine precedes startLine")
    for column in ("startColumn", "endColumn"):
        if column in region and (type(region[column]) is not int or region[column] < 1):
            raise ValueError(f"{prefix}.{column} must be a positive integer")
    if start is not None and (end is None or end == start):
        if "endColumn" in region and region["endColumn"] < region.get("startColumn", 1):
            raise ValueError(f"{prefix}.endColumn precedes startColumn")
    for offset, length in (("charOffset", "charLength"), ("byteOffset", "byteLength")):
        if offset in region and (
            type(region[offset]) is not int or region[offset] < -1
        ):
            raise ValueError(f"{prefix}.{offset} must be an integer of at least -1")
        if length in region:
            size = region[length]
            if type(size) is not int or size < 0:
                raise ValueError(f"{prefix}.{length} must be a non-negative integer")
    if not any(key in region for key in ("startLine", "charOffset", "byteOffset")):
        raise ValueError(f"{prefix} requires startLine, charOffset, or byteOffset")
    snippet = region.get("snippet")
    if "snippet" in region and (
        not isinstance(snippet, dict)
        or not {"text", "binary"} & snippet.keys()
        or any(
            not isinstance(snippet[key], str)
            for key in ("text", "binary")
            if key in snippet
        )
    ):
        raise ValueError(f"{prefix}.snippet must contain text or binary strings")


def _validate_triage_properties(properties: dict[str, Any], prefix: str) -> None:
    if METIS_FINDING_ID_KEY in properties and not isinstance(
        properties[METIS_FINDING_ID_KEY], str
    ):
        raise ValueError(f"{prefix} {METIS_FINDING_ID_KEY} must be a string")
    if (
        METIS_TRIAGED_KEY in properties
        and type(properties[METIS_TRIAGED_KEY]) is not bool
    ):
        raise ValueError(f"{prefix} {METIS_TRIAGED_KEY} must be a boolean")
    for key in (
        METIS_TRIAGE_STATUS_KEY,
        METIS_TRIAGE_REASON_KEY,
        METIS_TRIAGE_TIMESTAMP_KEY,
    ):
        if key in properties and not isinstance(properties[key], str):
            raise ValueError(f"{prefix} {key} must be a string")
    for key in (
        METIS_EVIDENCE_REQUIREMENTS_KEY,
        METIS_MISSING_EVIDENCE_KEY,
        METIS_TRIAGE_EVIDENCE_KEY,
        METIS_TRIAGE_RESOLUTION_CHAIN_KEY,
        METIS_TRIAGE_UNRESOLVED_HOPS_KEY,
        METIS_TRIAGE_VALIDATION_ERRORS_KEY,
    ):
        if key in properties and (
            not isinstance(properties[key], list)
            or any(not isinstance(item, str) for item in properties[key])
        ):
            raise ValueError(f"{prefix} {key} must be an array of strings")
    if (
        METIS_TRIAGE_DECISION_SOURCE_KEY in properties
        and properties[METIS_TRIAGE_DECISION_SOURCE_KEY] not in TRIAGE_DECISION_SOURCES
    ):
        raise ValueError(
            f"{prefix} {METIS_TRIAGE_DECISION_SOURCE_KEY} must be "
            f"{', '.join(TRIAGE_DECISION_SOURCES[:-1])}, or {TRIAGE_DECISION_SOURCES[-1]}"
        )
    coverage = properties.get(METIS_EVIDENCE_COVERAGE_KEY)
    if METIS_EVIDENCE_COVERAGE_KEY in properties and (
        not isinstance(coverage, dict)
        or any(
            not isinstance(key, str) or type(value) is not int or value < 0
            for key, value in coverage.items()
        )
    ):
        raise ValueError(
            f"{prefix} {METIS_EVIDENCE_COVERAGE_KEY} must map strings to counts"
        )
    threat_policy = properties.get(METIS_THREAT_MODEL_POLICY_KEY)
    if METIS_THREAT_MODEL_POLICY_KEY in properties and not isinstance(
        threat_policy, dict
    ):
        raise ValueError(f"{prefix} {METIS_THREAT_MODEL_POLICY_KEY} must be an object")


def _nonempty_string(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and bool(value.strip())
