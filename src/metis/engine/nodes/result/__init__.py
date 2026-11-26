# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Terminal result nodes."""

from metis import runlog
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeResult


def _emit_result_artifact(
    kind: str, name: str, invocation: NodeInvocation, result: NodeResult
) -> None:
    stream = invocation.context.output
    runlog.event(
        "artifact",
        {
            "kind": kind,
            "formats": invocation.formats or (),
            "payload": stream.reference(name)
            if stream is not None and getattr(stream, name) is not None
            else result.outputs,
        },
    )
