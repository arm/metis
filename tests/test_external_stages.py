# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import sys

import pytest

from metis.engine.external_stages.service import ExternalStageService


def test_external_stage_pipeline_invokes_black_boxes_and_applies_decisions(tmp_path):
    codebase = tmp_path / "codebase"
    codebase.mkdir()
    (codebase / "unsafe.c").write_text("gets(buf);\n", encoding="utf-8")
    script = tmp_path / "black_box.py"
    script.write_text(_BLACK_BOX_SCRIPT, encoding="utf-8")

    service = ExternalStageService(
        codebase_path=str(codebase),
        config={
            "analysis": {
                "fake": {
                    "command": [
                        sys.executable,
                        str(script),
                        "analysis",
                        "{codebase_path}",
                        "{output_sarif}",
                    ],
                    "timeout_seconds": 10,
                }
            },
            "validation": {
                "fake": {
                    "command": [
                        sys.executable,
                        str(script),
                        "validation",
                        "{codebase_path}",
                        "{input_sarif}",
                        "{output_decision}",
                    ],
                    "timeout_seconds": 10,
                }
            },
        },
    )

    result = service.run_pipeline(
        analysis="fake",
        validation="fake",
        prompt="find security issues in this codebase",
        run_dir=tmp_path / "run",
    )

    assert result.analysis.output_sarif.is_file()
    assert result.validation is not None
    assert result.validation.validated_sarif.is_file()
    payload = json.loads(result.validation.validated_sarif.read_text(encoding="utf-8"))
    props = payload["runs"][0]["results"][0]["properties"]
    assert props["metisTriaged"] is True
    assert props["metisTriageStatus"] == "valid"
    assert props["metisTriageReason"] == "Confirmed by fake validator."
    assert props["metisMissingEvidence"] == []


def test_external_analysis_rejects_config_without_required_bindings(tmp_path):
    codebase = tmp_path / "codebase"
    codebase.mkdir()
    service = ExternalStageService(
        codebase_path=str(codebase),
        config={
            "analysis": {
                "broken": {
                    "command": ["fake-tool", "{codebase_path}"],
                    "timeout_seconds": 10,
                }
            }
        },
    )

    with pytest.raises(ValueError, match="must reference"):
        service.run_analysis(
            "broken",
            prompt="find security issues in this codebase",
            run_dir=tmp_path / "run",
        )


_BLACK_BOX_SCRIPT = r"""
import json
import sys

mode = sys.argv[1]
if mode == "analysis":
    codebase_path = sys.argv[2]
    output_sarif = sys.argv[3]
    with open(output_sarif, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [
                    {
                        "tool": {"driver": {"name": "fake-analysis", "rules": []}},
                        "results": [
                            {
                                "ruleId": "FAKE001",
                                "level": "error",
                                "message": {"text": "Unsafe input function"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "unsafe.c"},
                                            "region": {
                                                "startLine": 1,
                                                "snippet": {"text": "gets(buf);"},
                                            },
                                        }
                                    }
                                ],
                                "properties": {"codebase": codebase_path},
                            }
                        ],
                    }
                ],
            },
            handle,
        )
elif mode == "validation":
    codebase_path = sys.argv[2]
    input_sarif = sys.argv[3]
    output_decision = sys.argv[4]
    assert codebase_path
    assert input_sarif
    with open(output_decision, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "contract_version": "metis.external.validation-result/v1",
                "decisions": [
                    {
                        "run_index": 0,
                        "result_index": 0,
                        "status": "valid",
                        "reason": "Confirmed by fake validator.",
                        "evidence": ["unsafe.c:1"],
                        "resolution_chain": ["SARIF finding -> unsafe.c:1"],
                        "unresolved_hops": [],
                    }
                ],
            },
            handle,
        )
else:
    raise SystemExit(f"unknown mode: {mode}")
"""
