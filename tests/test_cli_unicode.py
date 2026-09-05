# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
import os

import pytest

from metis import runlog
from test_cli_e2e import run_cli
from test_execution_e2e import extension_graph
from test_execution_e2e import (
    installed_execution_extension as installed_execution_extension,
)
from test_execution_e2e import write_execution_config


@pytest.mark.skipif(os.name != "posix", reason="POSIX filesystem surrogate decoding")
def test_cli_records_surrogate_arguments_in_complete_trace(
    installed_execution_extension, tmp_path
):
    write_execution_config(tmp_path / "metis.yaml", extension_graph())
    project = os.fsdecode(b"project-\xff")
    trace = tmp_path / "trace.ndjson"
    output = tmp_path / "report.json"
    completed = run_cli(
        installed_execution_extension,
        tmp_path,
        "--quiet",
        "--project-schema",
        project,
        "--log-workflow-debug",
        "--log-workflow-debug-path",
        trace.name,
        "--output-file",
        output.name,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(output.read_text())["reviews"]
    assert runlog.validate_runlog(trace).status == "ok"
    metadata = json.loads(trace.with_suffix(".ndjson.meta.json").read_text())
    assert project in metadata["metadata"]["argv"]
    records = [json.loads(line) for line in trace.read_text().splitlines()]
    assert any(
        record["name"] == "artifact.written"
        and record["attributes"]["path"] == str(output)
        for record in records
    )
