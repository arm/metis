# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
import json
import math
from pathlib import Path
from typing import Any
from typing import TypeGuard

from metis.json_io import atomic_text_writer
from metis.sarif.triage import METIS_EVIDENCE_COVERAGE_KEY
from metis.sarif.triage import METIS_EVIDENCE_REQUIREMENTS_KEY
from metis.sarif.triage import METIS_FINDING_ID_KEY
from metis.sarif.triage import METIS_MISSING_EVIDENCE_KEY
from metis.sarif.triage import METIS_THREAT_MODEL_POLICY_KEY
from metis.sarif.triage import METIS_TRIAGED_KEY
from metis.sarif.triage import METIS_TRIAGE_REASON_KEY
from metis.sarif.triage import METIS_TRIAGE_STATUS_KEY
from metis.sarif.triage import METIS_TRIAGE_TIMESTAMP_KEY
from metis.sarif.writer import SARIF_VERSION


@dataclass(frozen=True, slots=True)
class SarifLimits:
    max_bytes: int = 25 * 1024 * 1024
    max_depth: int = 32
    max_nodes: int = 200_000
    max_mapping_keys: int = 100_000
    max_string_bytes: int = 64 * 1024
    max_array_items: int = 10_000
    max_findings: int = 10_000

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


DEFAULT_SARIF_LIMITS = SarifLimits()


def parse_metis_sarif(
    data: bytes,
    *,
    limits: SarifLimits = DEFAULT_SARIF_LIMITS,
) -> dict[str, Any]:
    """Parse and validate one bounded UTF-8 SARIF document."""
    payload = _parse_json_object(data, limits)
    validate_metis_sarif(payload, limits=limits)
    return payload


def _parse_json_object(data: bytes, limits: SarifLimits) -> dict[str, Any]:
    if not isinstance(data, bytes):
        raise TypeError("JSON data must be bytes")
    if len(data) > limits.max_bytes:
        raise ValueError("JSON exceeds the byte limit")
    if data.startswith(b"\xef\xbb\xbf"):
        raise ValueError("JSON must not contain a UTF-8 byte order mark")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("JSON must be valid UTF-8") from None

    def object_from_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("JSON contains a duplicate mapping key")
            value[key] = item
        return value

    def reject_constant(_value):
        raise ValueError("JSON contains a non-finite number")

    try:
        payload = json.loads(
            text,
            object_pairs_hook=object_from_pairs,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("Input must contain exactly one valid JSON document") from None
    if not isinstance(payload, dict):
        raise ValueError("JSON payload must be an object")
    _validate_json_tree(payload, limits)
    return payload


def load_metis_sarif_file(
    path: str | Path,
    *,
    limits: SarifLimits = DEFAULT_SARIF_LIMITS,
) -> dict[str, Any]:
    """Bound the file read before parsing and validating Metis SARIF."""
    payload = load_json_object_file(path, limits=limits)
    validate_metis_sarif(payload, limits=limits)
    return payload


def load_json_object_file(
    path: str | Path,
    *,
    limits: SarifLimits = DEFAULT_SARIF_LIMITS,
) -> dict[str, Any]:
    """Read a bounded JSON object for a SARIF or external decision contract."""
    with Path(path).open("rb") as stream:
        data = stream.read(limits.max_bytes + 1)
    return _parse_json_object(data, limits)


def save_metis_sarif_file(
    path: str | Path,
    payload: dict[str, Any],
    *,
    limits: SarifLimits = DEFAULT_SARIF_LIMITS,
) -> None:
    """Validate and atomically publish compact UTF-8 SARIF within its limits."""
    validate_metis_sarif(payload, limits=limits)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with atomic_text_writer(target, mode=0o600) as stream:
        for chunk in _bounded_json_chunks(payload, limits):
            stream.write(chunk)


def _bounded_json_chunks(payload: dict[str, Any], limits: SarifLimits) -> Iterator[str]:
    encoder = json.JSONEncoder(
        ensure_ascii=False, allow_nan=False, separators=(",", ":")
    )
    total = 0
    for chunk in encoder.iterencode(payload):
        total += len(chunk.encode("utf-8"))
        if total > limits.max_bytes:
            raise ValueError("SARIF exceeds the byte limit")
        yield chunk


def validate_metis_sarif(
    payload: dict[str, Any],
    *,
    limits: SarifLimits = DEFAULT_SARIF_LIMITS,
) -> None:
    """Validate bounded Metis SARIF structure."""
    if not isinstance(payload, dict):
        raise ValueError("SARIF payload must be a JSON object")
    _validate_json_tree(payload, limits)
    for _ in _bounded_json_chunks(payload, limits):
        pass

    if payload.get("version") != SARIF_VERSION:
        raise ValueError(f"Metis SARIF must use version {SARIF_VERSION}")
    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise ValueError("Metis SARIF must contain a runs array")
    finding_count = 0
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValueError(f"Metis SARIF run {run_index} must be an object")
        finding_count += _validate_run(run, run_index)
        if finding_count > limits.max_findings:
            raise ValueError("Metis SARIF exceeds the finding limit")


def _validate_json_tree(payload: dict[str, Any], limits: SarifLimits) -> None:
    stack: list[tuple[Any, int]] = [(payload, 1)]
    nodes = 0
    mapping_keys = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > limits.max_nodes:
            raise ValueError("JSON exceeds the constructed-node limit")
        if depth > limits.max_depth:
            raise ValueError("JSON exceeds the nesting limit")
        if isinstance(value, dict):
            mapping_keys += len(value)
            nodes += len(value)
            if mapping_keys > limits.max_mapping_keys:
                raise ValueError("JSON exceeds the mapping-key limit")
            if nodes > limits.max_nodes:
                raise ValueError("JSON exceeds the constructed-node limit")
            for key, item in value.items():
                if type(key) is not str:
                    raise ValueError("JSON mapping keys must be strings")
                _validate_string(key, limits)
                stack.append((item, depth + 1))
        elif isinstance(value, list):
            if len(value) > limits.max_array_items:
                raise ValueError("JSON exceeds the array-item limit")
            stack.extend((item, depth + 1) for item in value)
        elif type(value) is str:
            _validate_string(value, limits)
        elif type(value) is float:
            if not math.isfinite(value):
                raise ValueError("JSON contains a non-finite number")
        elif value is not None and type(value) not in {bool, int}:
            raise ValueError("JSON payload must contain only JSON values")


def _validate_string(value: str, limits: SarifLimits) -> None:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("JSON strings must contain Unicode scalar values") from None
    if len(encoded) > limits.max_string_bytes:
        raise ValueError("JSON exceeds the string limit")


def _validate_run(
    run: dict[str, Any],
    run_index: int,
) -> int:
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
    return len(results)


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
    for key in (METIS_EVIDENCE_REQUIREMENTS_KEY, METIS_MISSING_EVIDENCE_KEY):
        if key in properties and (
            not isinstance(properties[key], list)
            or any(not isinstance(item, str) for item in properties[key])
        ):
            raise ValueError(f"{prefix} {key} must be an array of strings")
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
