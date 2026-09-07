# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

from metis.engine.external_stages.service import (
    validate_metis_sarif as external_validate,
)
from metis.sarif.validation import SarifLimits
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


def test_parse_sarif_validates_exact_byte_limit():
    data = _encoded(_payload())
    limits = SarifLimits(max_bytes=len(data))

    assert parse_metis_sarif(data, limits=limits)["version"] == "2.1.0"

    with pytest.raises(ValueError, match="byte limit"):
        parse_metis_sarif(data, limits=SarifLimits(max_bytes=len(data) - 1))


def test_load_sarif_file_bounds_input_before_parsing(tmp_path):
    path = tmp_path / "result.sarif"
    data = _encoded(_payload())
    path.write_bytes(data)

    assert load_metis_sarif_file(path, limits=SarifLimits(max_bytes=len(data)))
    with pytest.raises(ValueError, match="byte limit"):
        load_metis_sarif_file(path, limits=SarifLimits(max_bytes=len(data) - 1))


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


def test_validate_sarif_enforces_injected_structural_limits_at_boundary():
    payload = _payload()

    validate_metis_sarif(
        payload,
        limits=SarifLimits(
            max_depth=10,
            max_nodes=34,
            max_mapping_keys=15,
            max_string_bytes=16,
            max_array_items=1,
            max_findings=1,
        ),
    )

    limits_and_messages = (
        ({"max_depth": 9}, "nesting"),
        ({"max_nodes": 33}, "constructed-node"),
        ({"max_mapping_keys": 14}, "mapping-key"),
        ({"max_string_bytes": 15}, "string limit"),
    )
    for override, message in limits_and_messages:
        with pytest.raises(ValueError, match=message):
            validate_metis_sarif(payload, limits=SarifLimits(**override))

    two_results = _payload(_result(), _result("src/b.py"))
    with pytest.raises(ValueError, match="array-item"):
        validate_metis_sarif(
            two_results,
            limits=SarifLimits(max_array_items=1, max_findings=2),
        )
    with pytest.raises(ValueError, match="finding limit"):
        validate_metis_sarif(two_results, limits=SarifLimits(max_findings=1))


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
    result = _result()
    with pytest.raises(ValueError, match="constructed-node"):
        validate_metis_sarif(_payload(result, result), limits=SarifLimits(max_nodes=34))


@pytest.mark.parametrize("container", [dict, list])
def test_validate_sarif_rejects_cycles_with_bounded_traversal(container):
    cycle = container()
    if isinstance(cycle, dict):
        cycle["self"] = cycle
    else:
        cycle.append(cycle)
    payload = _payload()
    payload["extension"] = cycle
    with pytest.raises(ValueError, match="recursive|nesting|constructed-node"):
        validate_metis_sarif(payload, limits=SarifLimits(max_depth=12, max_nodes=100))


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


def test_save_sarif_enforces_exact_utf8_size_and_preserves_previous_output(tmp_path):
    path = tmp_path / "result.sarif"
    payload = _payload()
    payload["runs"][0]["results"][0]["message"]["text"] = "Caf\u00e9 \U0001f40d"
    encoded = _encoded(payload)
    limits = SarifLimits(max_bytes=len(encoded))
    save_metis_sarif_file(path, payload, limits=limits)
    assert path.read_bytes() == encoded
    assert load_metis_sarif_file(path, limits=limits) == payload
    with pytest.raises(ValueError, match="byte limit"):
        save_metis_sarif_file(
            path, payload, limits=SarifLimits(max_bytes=len(encoded) - 1)
        )
    assert path.read_bytes() == encoded
    payload["runs"][0]["results"][0]["message"]["text"] = ""
    with pytest.raises(ValueError, match="message.text"):
        save_metis_sarif_file(path, payload)
    assert path.read_bytes() == encoded
