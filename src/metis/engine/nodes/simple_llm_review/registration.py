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
from metis.engine.stages.review.models import ReviewStatus
from metis.engine.stages.review.models import StandardReviewResult
from metis.engine.stages.review.checkpoints import ReviewCheckpointSession
from metis.engine.stages.review.scope import select_review_targets

from .service import SimpleLlmReviewService

NODE_NAME = "simple_llm_review"

if TYPE_CHECKING:
    from metis.engine.capabilities.index import IndexCapability
    from metis.engine.capabilities.navigation import NavigationCapability
    from metis.memory import MemoryService


def create_node(service: SimpleLlmReviewService) -> NodeRegistration:
    def execute(invocation: NodeInvocation) -> NodeResult:
        command = cast(ReviewCommand, invocation.inputs["request"])
        output = None
        options = {}
        callbacks = invocation.context.callbacks
        checkpoint_session = None
        stream = invocation.context.output
        if stream is not None and "review" in stream.stages:
            files = (
                ()
                if command.mode == "patch"
                else select_review_targets(invocation.context.repository, command)
            )
            output = stream.open_review(command, files)
            options = {
                "emit": output.append,
                "on_summary": output.add_summary,
                "summary_input": output.issues,
                "begin_patch_entry": output.begin_patch_entry,
                "files": files,
            }
        elif callbacks.checkpoint is not None or callbacks.resume is not None:
            checkpoint_session = ReviewCheckpointSession(NODE_NAME, callbacks)
        memory = cast(
            "MemoryService | None", invocation.context.capabilities.get("memory")
        )
        index = cast(
            "IndexCapability | None",
            invocation.context.capabilities.get("index"),
        )
        review = service.run_review(
            command,
            jobs=invocation.context.jobs,
            model=invocation.context.runtime.model,
            memory_service=memory,
            index=index,
            navigation=cast(
                "NavigationCapability | None",
                invocation.context.capabilities.get("navigation"),
            ),
            progress_callback=invocation.context.callbacks.progress,
            checkpoint_session=checkpoint_session,
            **options,
        )
        if review.result is None and output is not None and output.count:
            review = ReviewRun(
                ReviewStatus.INCONCLUSIVE,
                StandardReviewResult(reviews=[]),
                review.diagnostics,
            )
        return review_node_result(review)

    return NodeRegistration(
        name=NODE_NAME,
        stage="review",
        configuration=EmptyNodeConfiguration,
        inputs={"request": ReviewCommand},
        outputs={"review": ReviewRun},
        execute=execute,
        capabilities={
            "index": CapabilityRequirement.OPTIONAL,
            "memory": CapabilityRequirement.OPTIONAL,
            "navigation": CapabilityRequirement.OPTIONAL,
        },
    )
