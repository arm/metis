# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import cast

from metis.engine.codegraph import CodeGraphReference
from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import ExecutionStatus
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.execution.contracts import ResultFormat
from metis.engine.stages.review.execution import combine_review_runs
from metis.engine.stages.review.models import ReviewResult
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import ReviewStatus
from metis.sarif.models import SarifPayload
from metis.sarif.writer import generate_sarif
from metis import runlog


def execute(invocation: NodeInvocation) -> NodeResult:
    reviews = cast(tuple[ReviewRun, ...], invocation.inputs["reviews"])
    codegraph = cast(CodeGraphReference | None, invocation.inputs["codegraph"])
    combined = combine_review_runs(reviews)
    if combined.result is None:
        raise ValueError("Review produced no result")
    findings = combined.result
    sarif = SarifPayload.model_validate(
        generate_sarif(findings.model_dump(mode="python"))
    )
    result = NodeResult(
        {
            "formats": invocation.formats or (),
            "filename": invocation.filename,
            "findings": findings,
            "sarif": sarif,
            "codegraph": codegraph,
        },
        status=_execution_status(combined.status),
    )
    runlog.event(
        "artifact",
        {
            "kind": "review_result",
            "formats": invocation.formats or (),
            "payload": result.outputs,
        },
    )
    return result


registration = NodeRegistration(
    name="result",
    stage="review",
    configuration=EmptyNodeConfiguration,
    inputs={"reviews": tuple[ReviewRun, ...], "codegraph": CodeGraphReference | None},
    outputs={
        "formats": tuple[ResultFormat, ...],
        "filename": str | None,
        "findings": ReviewResult,
        "sarif": SarifPayload,
        "codegraph": CodeGraphReference | None,
    },
    execute=execute,
)


def _execution_status(status: ReviewStatus) -> ExecutionStatus:
    if status is ReviewStatus.INCONCLUSIVE:
        return ExecutionStatus.INCONCLUSIVE
    return ExecutionStatus.OK
