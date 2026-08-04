# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.engine.codegraph import CodeGraphReference

from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult


def execute(invocation: NodeInvocation) -> NodeResult:
    reference = invocation.context.codegraphs.materialize(
        progress_callback=invocation.context.callbacks.progress,
    )
    return NodeResult({"codegraph": reference})


registration = NodeRegistration(
    name="codegraph",
    stage="review",
    configuration=EmptyNodeConfiguration,
    inputs={},
    outputs={"codegraph": CodeGraphReference},
    execute=execute,
)
