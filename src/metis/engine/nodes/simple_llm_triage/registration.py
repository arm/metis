# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import cast
from typing import TYPE_CHECKING
from functools import partial

from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import CapabilityRequirement
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.stages.triage.models import TriageRun

if TYPE_CHECKING:
    from .service import SimpleLlmTriageService
    from metis.engine.capabilities.navigation import NavigationCapability
    from metis.memory import MemoryService


def create_node(
    simple_llm: SimpleLlmTriageService,
) -> NodeRegistration:
    def execute(invocation: NodeInvocation) -> NodeResult:
        adjudicator = invocation.context.triage
        if adjudicator is None:
            raise RuntimeError("Triage adjudication is unavailable")
        memory = cast(
            "MemoryService | None", invocation.context.capabilities.get("memory")
        )
        navigation = cast(
            "NavigationCapability",
            invocation.context.capabilities["navigation"],
        )
        triaged = adjudicator.triage_run(
            cast(TriageRun, invocation.inputs["request"]),
            classifier=partial(
                simple_llm.classify,
                navigation=navigation,
                model_tool_max_rounds=(
                    invocation.context.runtime.model_tool_max_rounds
                ),
            ),
            memory_service=memory,
            progress_callback=invocation.context.callbacks.progress,
            debug_callback=invocation.context.callbacks.debug,
            checkpoint_callback=invocation.context.callbacks.checkpoint,
        )
        return NodeResult({"run": triaged})

    return NodeRegistration(
        name="simple_llm_triage",
        stage="triage",
        configuration=EmptyNodeConfiguration,
        inputs={"request": TriageRun},
        outputs={"run": TriageRun},
        execute=execute,
        capabilities={
            "memory": CapabilityRequirement.OPTIONAL,
            "navigation": CapabilityRequirement.REQUIRED,
        },
    )
