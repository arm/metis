# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import logging
from typing import cast

from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.llm_runner import JsonPromptRequest
from metis.engine.llm_runner import rendered_prompt_token_count
from metis.engine.prompt_catalog import get_engine_prompts
from metis.engine.stages.review.execution import combine_review_runs
from metis.engine.stages.review.models import FinalReviewRun
from metis.engine.stages.review.models import PatchReviewResult
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import StandardReviewResult
from metis.usage import usage_operation

from .core import DeduplicationDecision
from .core import consolidate_result

logger = logging.getLogger(__name__)
SYSTEM_PROMPT = get_engine_prompts("finding_dedup", required=("system",))["system"]
USER_PROMPT = "Candidate findings JSON:\n{candidate_findings}"


def _parse_decision(raw: object) -> DeduplicationDecision | None:
    if isinstance(raw, DeduplicationDecision):
        return raw
    if isinstance(raw, dict):
        try:
            return DeduplicationDecision.model_validate(raw)
        except ValueError:
            return None
    return None


def execute(invocation: NodeInvocation) -> NodeResult:
    reviews = cast(tuple[ReviewRun, ...], invocation.inputs["reviews"])
    combined = combine_review_runs(reviews)
    result = combined.result
    if result is None or isinstance(result, PatchReviewResult):
        return NodeResult({"review": FinalReviewRun(combined)})
    assert isinstance(result, StandardReviewResult)
    candidate_count = sum(len(group.reviews) for group in result.reviews)
    progress = invocation.context.callbacks.progress
    if progress is not None:
        progress(
            {
                "event": "findings_finalization_start",
                "candidates": candidate_count,
            }
        )

    def report_progress(payload: dict[str, object]) -> None:
        if progress is not None:
            progress({"event": "findings_finalization_progress", **payload})

    def adjudicate(
        candidates: list[dict[str, object]],
    ) -> DeduplicationDecision | None:
        with usage_operation("finding_dedup"):
            return invocation.context.prompts.invoke(
                JsonPromptRequest(
                    model=invocation.context.runtime.model,
                    temperature=0.1,
                    system_prompt=SYSTEM_PROMPT,
                    user_prompt=USER_PROMPT,
                    variables={
                        "candidate_findings": json.dumps(
                            candidates, separators=(",", ":")
                        )
                    },
                    parse=_parse_decision,
                    response_model=DeduplicationDecision,
                    logger=logger,
                    label="Final review deduplication",
                    batch_size=len(candidates),
                    invalid_message="expected duplicate groups JSON",
                    final_keep_message="keeping this batch unchanged",
                    chat_model_kwargs=dict(
                        invocation.context.runtime.chat_model_kwargs
                    ),
                )
            )

    def packet_fits(candidates: list[dict[str, object]]) -> bool:
        candidate_json = json.dumps(candidates, separators=(",", ":"))
        request_tokens = rendered_prompt_token_count(
            invocation.context.runtime.token_counter,
            system_prompt=SYSTEM_PROMPT,
            user_prompt=USER_PROMPT,
            variables={"candidate_findings": candidate_json},
        )
        schema_tokens = invocation.context.runtime.token_counter(
            json.dumps(DeduplicationDecision.model_json_schema(), separators=(",", ":"))
        )
        return (
            request_tokens + schema_tokens
            <= invocation.context.runtime.max_token_length
        )

    deduped = consolidate_result(
        result,
        adjudicator=adjudicate,
        packet_fits=packet_fits,
        progress_callback=report_progress,
        jobs=invocation.context.jobs,
    )
    if progress is not None:
        kept_count = sum(len(group.reviews) for group in deduped.reviews)
        progress(
            {
                "event": "findings_finalization_done",
                "raw_findings": candidate_count,
                "deduped_findings": kept_count,
                "removed_findings": candidate_count - kept_count,
            }
        )
    return NodeResult(
        {
            "review": FinalReviewRun(
                ReviewRun(combined.status, deduped, combined.diagnostics)
            )
        }
    )


registration = NodeRegistration(
    name="finding_dedup",
    stage="review",
    configuration=EmptyNodeConfiguration,
    inputs={"reviews": tuple[ReviewRun, ...]},
    outputs={"review": FinalReviewRun},
    execute=execute,
)
