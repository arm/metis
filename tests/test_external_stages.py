# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import json
import sys
from unittest.mock import AsyncMock
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from metis.engine.external_stages.schemas import ExternalValidationDecisionModel
from metis.engine.external_stages.schemas import ExternalStageCommandModel
from metis.engine.external_stages.runner import ExternalStageRunner
from metis.engine.external_stages.service import ExternalStageService


@pytest.mark.parametrize(
    "fields",
    (
        {"status": "valid"},
        {"status": "valid", "evidence": ["source.c:1"]},
        {"status": "inconclusive"},
    ),
)
def test_external_validation_decision_validates_missing_evidence(fields):
    payload = {"run_index": 0, "result_index": 0, "reason": "Checked.", **fields}

    with pytest.raises(ValidationError):
        ExternalValidationDecisionModel.model_validate(payload)


@pytest.mark.parametrize("already_exited", (False, True))
def test_external_stage_cancellation_reaps_process(monkeypatch, already_exited):
    process = Mock(returncode=-9)
    process.communicate = AsyncMock(side_effect=[asyncio.CancelledError(), (b"", b"")])
    if already_exited:
        process.kill.side_effect = ProcessLookupError()
    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", AsyncMock(return_value=process)
    )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            ExternalStageRunner().run(
                ExternalStageCommandModel(command=["local-test"]), bindings={}
            )
        )

    process.kill.assert_called_once_with()
    assert process.communicate.await_count == 2


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


@pytest.mark.parametrize("command", [[], [""], ["   "]])
def test_external_command_rejects_missing_executable(command):
    with pytest.raises(ValidationError):
        ExternalStageCommandModel(command=command)


@pytest.mark.parametrize("argument", ["", "  payload  "])
def test_external_command_preserves_literal_arguments(argument):
    stage = ExternalStageCommandModel(
        command=[sys.executable, "-c", "import sys; print(repr(sys.argv[1]))", argument]
    )
    result = ExternalStageRunner().run_sync(stage, bindings={})
    assert result.stdout.strip() == repr(argument)


@pytest.mark.parametrize("stage", ["analysis", "validation"])
@pytest.mark.parametrize("occupied", ["output", "request"])
def test_external_stage_rejects_previous_artifacts_before_launch(
    tmp_path, stage, occupied
):
    runner = Mock()
    service = ExternalStageService(
        codebase_path=str(tmp_path),
        config={stage: {"inert": {"command": ["local-test", "{request_path}"]}}},
        runner=runner,
    )
    directory = tmp_path / "run"
    directory.mkdir()
    output = "analysis.sarif" if stage == "analysis" else "validation-decision.json"
    previous = directory / (output if occupied == "output" else f"{stage}-request.json")
    previous.write_text("old artifact", encoding="utf-8")
    input_path = tmp_path / "empty.sarif"
    input_path.write_text(json.dumps({"version": "2.1.0", "runs": []}))
    with pytest.raises(FileExistsError):
        if stage == "analysis":
            service.run_analysis(
                "inert", prompt="echo local metadata", run_dir=directory
            )
        else:
            service.run_validation("inert", input_sarif=input_path, run_dir=directory)
    runner.run_sync.assert_not_called()
    assert previous.read_text() == "old artifact"


def test_concurrent_external_requests_cannot_share_artifacts(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from metis.engine.external_stages.runner import ExternalStageProcessResult

    started, release = Event(), Event()
    runner = Mock()

    def run(stage, *, bindings):
        started.set()
        assert release.wait(5)
        bindings["output_sarif"].write_text(
            json.dumps({"version": "2.1.0", "runs": []})
        )
        return ExternalStageProcessResult(("inert",), 0, "", "")

    runner.run_sync.side_effect = run
    service = ExternalStageService(
        codebase_path=str(tmp_path),
        config={"analysis": {"inert": {"command": ["local-test", "{request_path}"]}}},
        runner=runner,
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(
            service.run_analysis,
            "inert",
            prompt="local metadata",
            run_dir=tmp_path / "run",
        )
        try:
            assert started.wait(5)
            with pytest.raises(FileExistsError):
                service.run_analysis(
                    "inert", prompt="other metadata", run_dir=tmp_path / "run"
                )
        finally:
            release.set()
        assert first.result(timeout=5).output_sarif.is_file()
    runner.run_sync.assert_called_once()
