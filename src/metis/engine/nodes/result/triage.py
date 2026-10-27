# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import cast

from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.execution.contracts import ExecutionDiagnostic
from metis.engine.execution.contracts import ExecutionStatus
from metis.engine.execution.contracts import ResultFormat
from metis.engine.stages.triage.models import TRIAGE_FINDING_FAILED
from metis.engine.stages.triage.models import TriageRun
from metis.sarif.models import SarifPayload
from metis.sarif.triage import METIS_TRIAGE_DECISION_SOURCE_KEY
from metis.sarif.triage import METIS_TRIAGE_STATUS_KEY
from metis import runlog


def execute(invocation: NodeInvocation) -> NodeResult:
    stream = invocation.context.output
    output = stream.triage if stream is not None else None
    run = cast(TriageRun, invocation.inputs["run"])
    diagnostics = []
    status = ExecutionStatus.OK
    inconclusive_results = 0
    failed_results = 0

    def inspect_result(path, result):
        nonlocal inconclusive_results, failed_results
        if not isinstance(result, dict):
            return
        properties = (
            result
            if output is not None and output.is_review
            else result.get("properties")
        )
        if not isinstance(properties, dict):
            return
        if properties.get(METIS_TRIAGE_STATUS_KEY) == "inconclusive":
            inconclusive_results += 1
        if properties.get(METIS_TRIAGE_DECISION_SOURCE_KEY) == "execution_failure":
            failed_results += 1

    if output is None:
        for run_index, sarif_run in enumerate(run.sarif.runs):
            for result_index, result in enumerate(sarif_run.get("results") or ()):
                inspect_result(("runs", run_index, "results", result_index), result)
        remaining = len(run.remaining)
    else:
        stream.finish_triage(inspect_result)
        remaining = run.total - run.processed
    if failed_results:
        diagnostics.append(
            ExecutionDiagnostic(
                TRIAGE_FINDING_FAILED,
                f"Triage failed for {failed_results} finding(s)",
            )
        )
    if remaining or inconclusive_results:
        status = ExecutionStatus.INCONCLUSIVE
    if remaining:
        diagnostics.append(
            ExecutionDiagnostic(
                "triage.findings_unhandled",
                f"Triage left {remaining} finding(s) unchanged",
                "warning",
            )
        )
    output = NodeResult(
        {
            "formats": invocation.formats or (),
            "filename": invocation.filename,
            "sarif": run.sarif,
        },
        status=status,
        diagnostics=tuple(diagnostics),
    )
    runlog.event(
        "artifact",
        {
            "kind": "triage_result",
            "formats": invocation.formats or (),
            "payload": stream.reference("triage")
            if stream is not None and stream.triage is not None
            else output.outputs,
        },
    )
    return output


registration = NodeRegistration(
    name="result",
    stage="triage",
    configuration=EmptyNodeConfiguration,
    inputs={"run": TriageRun},
    outputs={
        "formats": tuple[ResultFormat, ...],
        "filename": str | None,
        "sarif": SarifPayload,
    },
    execute=execute,
)
