# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING
from typing import cast

from metis.engine.execution.contracts import CapabilityRequirement
from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.stages.review.execution import review_node_result
from metis.engine.stages.review.models import ReviewCommand
from metis.engine.stages.review.models import ReviewRun

from .service import SimpleLlmReviewService

if TYPE_CHECKING:
    from metis.engine.capabilities.index import IndexCapability
    from metis.memory import MemoryService


def create_node(service: SimpleLlmReviewService) -> NodeRegistration:
    def execute(invocation: NodeInvocation) -> NodeResult:
        memory = cast(
            "MemoryService | None", invocation.context.capabilities.get("memory")
        )
        index = cast(
            "IndexCapability | None",
            invocation.context.capabilities.get("index"),
        )
        review = service.run_review(
            cast(ReviewCommand, invocation.inputs["request"]),
            memory_service=memory,
            index=index,
            progress_callback=invocation.context.callbacks.progress,
        )
        return review_node_result(review)

    return NodeRegistration(
        name="simple_llm_review",
        stage="review",
        configuration=EmptyNodeConfiguration,
        inputs={"request": ReviewCommand},
        outputs={"review": ReviewRun},
        execute=execute,
        capabilities={
            "index": CapabilityRequirement.OPTIONAL,
            "memory": CapabilityRequirement.OPTIONAL,
        },
    )
