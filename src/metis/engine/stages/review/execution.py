# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.execution.contracts import ExecutionDiagnostic
from metis.engine.execution.contracts import ExecutionStatus
from metis.engine.execution.contracts import NodeResult

from .models import PatchReviewResult
from .models import ReviewGroup
from .models import ReviewResult
from .models import ReviewRun
from .models import ReviewStatus
from .models import StandardReviewResult


def review_node_result(review: ReviewRun) -> NodeResult:
    status = (
        ExecutionStatus.OK
        if review.status is ReviewStatus.SUCCEEDED
        else ExecutionStatus.INCONCLUSIVE
    )
    diagnostics = tuple(
        ExecutionDiagnostic(item.code, item.message, item.severity)
        for item in review.diagnostics
    )
    return NodeResult({"review": review}, status=status, diagnostics=diagnostics)


def combine_review_runs(reviews: tuple[ReviewRun, ...]) -> ReviewRun:
    diagnostics = tuple(
        diagnostic for review in reviews for diagnostic in review.diagnostics
    )
    completed = tuple(review for review in reviews if review.result is not None)
    if not completed:
        status = (
            ReviewStatus.FAILED
            if any(review.status is ReviewStatus.FAILED for review in reviews)
            else ReviewStatus.INCONCLUSIVE
        )
        return ReviewRun(status, None, diagnostics)
    status = (
        ReviewStatus.SUCCEEDED
        if all(review.status is ReviewStatus.SUCCEEDED for review in reviews)
        else ReviewStatus.INCONCLUSIVE
    )
    return ReviewRun(
        status,
        combine_review_results(
            tuple(review.result for review in completed if review.result is not None)
        ),
        diagnostics,
    )


def combine_review_results(results: tuple[ReviewResult, ...]) -> ReviewResult:
    patch_results = tuple(
        result for result in results if isinstance(result, PatchReviewResult)
    )
    standard_results = tuple(
        result for result in results if isinstance(result, StandardReviewResult)
    )
    if patch_results:
        if len(patch_results) != 1 or any(
            result.reviews for result in standard_results
        ):
            raise ValueError(
                "Patch review cannot be combined with code review findings"
            )
        return patch_results[0]

    groups: list[ReviewGroup] = []
    for result in standard_results:
        for group in result.reviews:
            if group.reviews:
                groups.append(group)

    return StandardReviewResult(reviews=groups)
