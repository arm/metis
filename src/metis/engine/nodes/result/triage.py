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
from metis.sarif.triage import METIS_TRIAGE_REASON_KEY
from metis.sarif.triage import METIS_TRIAGE_STATUS_KEY
from metis import runlog


def execute(invocation: NodeInvocation) -> NodeResult:
    run = cast(TriageRun, invocation.inputs["run"])
    diagnostics = []
    status = ExecutionStatus.OK
    inconclusive_results = 0
    for run_index, sarif_run in enumerate(run.sarif.runs):
        for result_index, result in enumerate(sarif_run.get("results") or ()):
            properties = result.get("properties") if isinstance(result, dict) else None
            if (
                isinstance(properties, dict)
                and properties.get(METIS_TRIAGE_STATUS_KEY) == "inconclusive"
            ):
                inconclusive_results += 1
            if (
                isinstance(properties, dict)
                and properties.get(METIS_TRIAGE_DECISION_SOURCE_KEY)
                == "execution_failure"
            ):
                diagnostics.append(
                    ExecutionDiagnostic(
                        TRIAGE_FINDING_FAILED,
                        f"Triage failed for run={run_index} result={result_index}: "
                        f"{properties.get(METIS_TRIAGE_REASON_KEY, 'No decision produced')}",
                    )
                )
    if run.remaining or inconclusive_results:
        status = ExecutionStatus.INCONCLUSIVE
    if run.remaining:
        diagnostics.append(
            ExecutionDiagnostic(
                "triage.findings_unhandled",
                f"Triage left {len(run.remaining)} finding(s) unchanged",
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
            "payload": output.outputs,
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
