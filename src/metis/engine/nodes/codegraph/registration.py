# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import cast

from metis.engine.codegraph import CodeGraphReference
from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.source import ProfiledSourceReference


def execute(invocation: NodeInvocation) -> NodeResult:
    profiled = cast(
        ProfiledSourceReference | None, invocation.inputs.get("profiled_source")
    )
    if (
        profiled is not None
        and profiled.fingerprint
        != invocation.context.repository.profiled_source_fingerprint
    ):
        raise RuntimeError(
            "CodeGraph source profile does not match the installed profile"
        )
    reference = invocation.context.codegraphs.materialize(
        progress_callback=invocation.context.report_progress,
    )
    if profiled is not None and any(
        invocation.context.repository.source_profile_applies_to_path(path)
        for path in reference.failed_files
    ):
        raise RuntimeError("Profiled CodeGraph contains failed files")
    return NodeResult({"codegraph": reference})


registration = NodeRegistration(
    name="codegraph",
    stage="initialize",
    configuration=EmptyNodeConfiguration,
    inputs={"profiled_source": ProfiledSourceReference | None},
    outputs={"codegraph": CodeGraphReference},
    execute=execute,
    required_when_bound=frozenset({"profiled_source"}),
)
