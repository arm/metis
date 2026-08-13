# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import cast

from metis import runlog
from metis.engine.codegraph import CodeGraphReference
from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import ExecutionStatus
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.execution.contracts import ResultFormat
from metis.engine.stages.review.models import FinalReviewRun
from metis.engine.stages.review.models import ReviewResult
from metis.engine.stages.review.models import ReviewStatus
from metis.sarif.models import SarifPayload
from metis.sarif.writer import generate_sarif


def execute(invocation: NodeInvocation) -> NodeResult:
    finalized = cast(FinalReviewRun, invocation.inputs["review"])
    codegraph = cast(CodeGraphReference | None, invocation.inputs["codegraph"])
    combined = finalized.review
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
        status=(
            ExecutionStatus.INCONCLUSIVE
            if combined.status is ReviewStatus.INCONCLUSIVE
            else ExecutionStatus.OK
        ),
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
    inputs={"review": FinalReviewRun, "codegraph": CodeGraphReference | None},
    outputs={
        "formats": tuple[ResultFormat, ...],
        "filename": str | None,
        "findings": ReviewResult,
        "sarif": SarifPayload,
        "codegraph": CodeGraphReference | None,
    },
    execute=execute,
)
