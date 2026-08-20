# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import cast

from metis.engine.codegraph import CodeGraphReference
from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.stages.review.models import ReviewCommand


def execute(invocation: NodeInvocation) -> NodeResult:
    command = cast(ReviewCommand, invocation.inputs["request"])
    reference = invocation.context.codegraphs.materialize(
        seed_file=command.target if command.mode == "file" else None,
        progress_callback=invocation.context.report_progress,
    )
    return NodeResult({"codegraph": reference})


registration = NodeRegistration(
    name="codegraph",
    stage="review",
    configuration=EmptyNodeConfiguration,
    inputs={"request": ReviewCommand},
    outputs={"codegraph": CodeGraphReference},
    execute=execute,
)
