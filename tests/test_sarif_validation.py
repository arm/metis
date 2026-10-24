# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

from metis.engine.external_stages.service import (
    validate_metis_sarif as external_validate,
)
from metis.sarif.triage import apply_triage_result
from metis.sarif.validation import load_metis_sarif_file
from metis.sarif.validation import parse_metis_sarif
from metis.sarif.validation import save_metis_sarif_file
from metis.sarif.validation import validate_metis_sarif
from metis.sarif.writer import generate_sarif


def _result(path: str = "src/a.py") -> dict:
    return {
        "ruleId": "R1",
        "message": {"text": "issue"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": 1},
                }
            }
        ],
    }


def _payload(*results: dict, path: str = "src/a.py") -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "test"}},
                "results": list(results or (_result(path),)),
            }
        ],
    }


def _encoded(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def test_external_stage_reexports_shared_validator_without_path_regression():
    assert external_validate is validate_metis_sarif
    validate_metis_sarif(_payload(path="/legacy/external-stage.c"))


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\xef\xbb\xbf" + _encoded(_payload()), "byte order mark"),
        (b"\xff", "valid UTF-8"),
        (b'{"version":"2.1.0","version":"2.1.0","runs":[]}', "duplicate"),
        (b'{"version":"2.1.0","runs":[],"value":NaN}', "non-finite"),
        (b'{"version":"2.1.0","runs":[]} {}', "one valid JSON document"),
        (b'{"version":"2.1.0","runs":[],"value":"\\ud800"}', "Unicode scalar"),
    ],
)
def test_parse_sarif_rejects_invalid_json_boundaries(data, message):
    with pytest.raises(ValueError, match=message):
        parse_metis_sarif(data)


@pytest.mark.parametrize("line", [True, "1", 0, 2_147_483_648])
def test_validate_sarif_requires_strict_bounded_line_numbers(line):
    payload = _payload()
    payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"][
        "startLine"
    ] = line

    with pytest.raises(ValueError, match="startLine"):
        validate_metis_sarif(payload)


def test_validate_sarif_checks_every_location():
    payload = _payload()
    payload["runs"][0]["results"][0]["locations"].append({"legacyExtension": True})

    with pytest.raises(ValueError, match="location 1"):
        validate_metis_sarif(payload)


@pytest.mark.parametrize(
    "decision_source", ["model", "validation_failure", "execution_failure", "policy"]
)
def test_validate_sarif_preserves_optional_triage_decision_metadata(decision_source):
    payload = _payload()
    payload["runs"][0]["results"][0]["properties"] = {
        "metisTriageEvidence": ["src/a.py:1"],
        "metisTriageResolutionChain": ["Source location inspected"],
        "metisTriageUnresolvedHops": [],
        "metisTriageDecisionSource": decision_source,
        "metisTriageValidationErrors": [],
    }
    assert parse_metis_sarif(_encoded(payload)) == payload
    assert apply_triage_result(
        payload,
        run_index=0,
        result_index=0,
        status="inconclusive",
        reason="Awaiting evidence",
        metadata={"decision_source": decision_source},
    )
    properties = payload["runs"][0]["results"][0]["properties"]
    assert properties["metisTriageDecisionSource"] == decision_source
    assert properties["metisTriaged"] is (decision_source != "execution_failure")
    assert parse_metis_sarif(_encoded(payload)) == payload


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("metisTriageEvidence", "src/a.py:1"),
        ("metisTriageResolutionChain", [1]),
        ("metisTriageUnresolvedHops", [None]),
        ("metisTriageValidationErrors", {}),
    ],
)
def test_validate_sarif_rejects_malformed_triage_decision_lists(key, value):
    payload = _payload()
    payload["runs"][0]["results"][0]["properties"] = {key: value}
    with pytest.raises(ValueError, match=key):
        validate_metis_sarif(payload)


@pytest.mark.parametrize("value", ["unknown", []])
def test_validate_sarif_rejects_unknown_triage_decision_sources(value):
    payload = _payload()
    payload["runs"][0]["results"][0]["properties"] = {
        "metisTriageDecisionSource": value
    }
    with pytest.raises(ValueError, match="metisTriageDecisionSource"):
        validate_metis_sarif(payload)


def test_validate_writer_output_with_shared_anchors_matches_json_roundtrip():
    anchor = {"file_path": "a.py", "start_line": 1, "end_line": 1}
    payload = generate_sarif(
        {
            "reviews": [
                {
                    "file": "a.py",
                    "reviews": [{"issue": str(i), "anchor": anchor} for i in range(2)],
                }
            ]
        }
    )
    first, second = payload["runs"][0]["results"]
    assert first["properties"]["anchor"] is second["properties"]["anchor"]
    validate_metis_sarif(payload)
    assert parse_metis_sarif(_encoded(payload)) == payload


@pytest.mark.parametrize("container", [dict, list])
def test_validate_sarif_rejects_cycles_without_size_limits(container):
    cycle = container()
    if isinstance(cycle, dict):
        cycle["self"] = cycle
    else:
        cycle.append(cycle)
    payload = _payload()
    payload["extension"] = cycle
    with pytest.raises(ValueError, match="recursive"):
        validate_metis_sarif(payload)


@pytest.mark.parametrize(
    "location",
    [
        {"logicalLocations": [{"fullyQualifiedName": "module.function"}]},
        {"physicalLocation": {"artifactLocation": {"uri": "src/b.py"}}},
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "data.bin"},
                "region": {
                    "byteOffset": 0,
                    "byteLength": 4,
                    "snippet": {"binary": "AA=="},
                },
            }
        },
        {"physicalLocation": {"address": {"absoluteAddress": 1}}},
    ],
)
def test_validate_sarif_preserves_supplementary_locations(location):
    payload = _payload()
    locations = payload["runs"][0]["results"][0]["locations"]
    locations[0]["physicalLocation"]["contextRegion"] = {
        "charOffset": 0,
        "charLength": 4,
    }
    locations.append(location)
    validate_metis_sarif(payload)
    locations[0] = location
    with pytest.raises(ValueError):
        validate_metis_sarif(payload)


@pytest.mark.parametrize(
    "location",
    [
        {"logicalLocations": "function"},
        {"physicalLocation": []},
        {"physicalLocation": {"artifactLocation": {"uri": 1}}},
        {"physicalLocation": {"region": {"byteOffset": -2}}},
        {"physicalLocation": {"region": {"byteOffset": 0, "byteLength": -1}}},
        {"physicalLocation": {"region": {"charOffset": 0, "charLength": True}}},
        {"physicalLocation": {"region": {"startLine": 2, "endLine": 1}}},
        {"physicalLocation": {"region": {"startLine": 1, "startColumn": 0}}},
        {
            "physicalLocation": {
                "region": {"startLine": 1, "startColumn": 3, "endColumn": 2}
            }
        },
    ],
)
def test_validate_sarif_rejects_malformed_supplementary_locations(location):
    payload = _payload()
    physical = location.get("physicalLocation")
    if isinstance(physical, dict) and "region" in physical:
        physical["artifactLocation"] = {"uri": "data.bin"}
    payload["runs"][0]["results"][0]["locations"].append(location)
    with pytest.raises(ValueError):
        validate_metis_sarif(payload)


def test_validate_sarif_preserves_unknown_offset_sentinels():
    payload = _payload()
    region = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "region"
    ]
    region.update(charOffset=-1, byteOffset=-1)
    validate_metis_sarif(payload)


def test_save_sarif_preserves_utf8_and_previous_output_on_invalid_report(tmp_path):
    path = tmp_path / "result.sarif"
    payload = _payload()
    payload["runs"][0]["results"][0]["message"]["text"] = "Caf\u00e9 \U0001f40d"
    encoded = _encoded(payload)
    save_metis_sarif_file(path, payload)
    assert path.read_bytes() == encoded
    assert load_metis_sarif_file(path) == payload
    payload["runs"][0]["results"][0]["message"]["text"] = ""
    with pytest.raises(ValueError, match="message.text"):
        save_metis_sarif_file(path, payload)
    assert path.read_bytes() == encoded
