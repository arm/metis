# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.reachability.models import FunctionNode
from metis.engine.reachability.supplementary_parsing import (
    _parse_combined,
    _parse_intra,
    _parse_semantic,
)


def _fn(unique_name, *, file_path="driver.c", line_number=10):
    return FunctionNode(
        unique_name=unique_name,
        file_path=file_path,
        name=unique_name.rsplit("::", 1)[-1],
        line_number=line_number,
        is_source=False,
        is_sink=False,
    )


def test_parse_intra_maps_function_and_line():
    target = _fn("driver.c::target", line_number=42)

    findings = _parse_intra(
        {
            "findings": [
                {
                    "function_name": "target",
                    "line": 45,
                    "description": "Unchecked length reaches copy",
                    "vulnerability_type": "buffer_overflow",
                    "confidence": "high",
                }
            ]
        },
        [target],
    )

    assert len(findings) == 1
    assert findings[0].source_function == "driver.c::target"
    assert findings[0].sink_function == "driver.c::target"
    assert findings[0].sink_line == 45
    assert findings[0].path == ["driver.c::target"]


def test_parse_combined_accepts_allowed_lifecycle_shapes_only():
    free_fn = _fn("driver.c::release_queue", line_number=20)
    use_fn = _fn("driver.c::queue_callback", line_number=80)

    findings = _parse_combined(
        {
            "findings": [
                {
                    "analysis_type": "lifecycle",
                    "free_function": "release_queue",
                    "use_function": "queue_callback",
                    "description": "Callback can use queue after release",
                },
                {
                    "analysis_type": "permission",
                    "function_name": "queue_callback",
                    "description": "Not part of this lens batch",
                },
            ]
        },
        [free_fn, use_fn],
        frozenset({"lifecycle"}),
    )

    assert len(findings) == 1
    assert findings[0].analysis_type == "lifecycle"
    assert findings[0].source_function == "driver.c::release_queue"
    assert findings[0].sink_function == "driver.c::queue_callback"
    assert findings[0].severity == "high"
    assert findings[0].vulnerability_type == "use_after_free"
    assert findings[0].path == [
        "driver.c::release_queue",
        "driver.c::queue_callback",
    ]


def test_parse_semantic_uses_related_function_as_source_context():
    setup_fn = _fn("driver.c::publish_state", line_number=12)
    use_fn = _fn("driver.c::consume_state", line_number=64)

    findings = _parse_semantic(
        {
            "findings": [
                {
                    "function_name": "consume_state",
                    "related_function": "publish_state",
                    "description": "State is consumed after incomplete publish",
                }
            ]
        },
        [setup_fn, use_fn],
        analysis_type="state_concurrency",
    )

    assert len(findings) == 1
    assert findings[0].analysis_type == "state_concurrency"
    assert findings[0].source_function == "driver.c::publish_state"
    assert findings[0].sink_function == "driver.c::consume_state"
    assert findings[0].path == [
        "driver.c::publish_state",
        "driver.c::consume_state",
    ]
