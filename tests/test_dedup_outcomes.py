# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import replace
from unittest.mock import Mock

import pytest

from metis.cli.review_progress import ReviewCodeProgressReporter
from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import ExecutionStatus
from metis.engine.execution.contracts import NodeCallbacks
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.nodes.finding_dedup.core import DeduplicationDecision
from metis.engine.nodes.finding_dedup.registration import execute
from metis.engine.stages.review.execution import combine_review_runs
from metis.engine.stages.review.models import ReviewDiagnostic
from metis.engine.stages.review.models import ReviewStatus
from test_execution_graph import _findings_run
from test_execution_graph import _node_context


@pytest.mark.parametrize("status", list(ReviewStatus))
@pytest.mark.parametrize("complete", [False, True])
def test_final_review_and_progress_preserve_dedup_outcome(status, complete, node_jobs):
    events = []
    original = ReviewDiagnostic("review.prior", "Earlier review diagnostic", "warning")
    review = replace(
        _findings_run(
            {"issue": "Unchecked copy", "line_number": 1},
            {"issue": "Unchecked length", "line_number": 2},
        ),
        status=status,
        diagnostics=(original,),
    )
    context = _node_context()
    context = replace(
        context,
        stage="review",
        prompts=Mock(
            invoke=Mock(
                return_value=DeduplicationDecision(groups=[]) if complete else None
            )
        ),
        runtime=replace(context.runtime, jobs=node_jobs),
        callbacks=NodeCallbacks(progress=events.append),
    )

    result = execute(
        NodeInvocation(EmptyNodeConfiguration(), {"reviews": (review,)}, context)
    )

    final = result.outputs["review"].review
    assert sum(len(group.reviews) for group in final.result.reviews) == 2
    assert result.status == (
        ExecutionStatus.OK if complete else ExecutionStatus.INCONCLUSIVE
    )
    expected = (original,) + tuple(
        ReviewDiagnostic(item.code, item.message, item.severity)
        for item in result.diagnostics
    )
    assert final.diagnostics == expected
    assert [item.code for item in result.diagnostics] == (
        [] if complete else ["review.dedup_failed"]
    )
    combined = combine_review_runs((review,))
    assert final.status == (
        ReviewStatus.INCONCLUSIVE
        if not complete and combined.status == ReviewStatus.SUCCEEDED
        else combined.status
    )
    assert events[-1] == {
        "event": "findings_finalization_done",
        "status": result.status.value,
        "failures": 0 if complete else 1,
        "raw_findings": 2,
        "deduped_findings": 2,
        "removed_findings": 0,
    }


def test_failed_review_without_findings_stays_failed():
    review = replace(_findings_run(), status=ReviewStatus.FAILED, result=None)
    context = _node_context()

    result = execute(
        NodeInvocation(EmptyNodeConfiguration(), {"reviews": (review,)}, context)
    )

    assert result.outputs["review"].review == review
    context.prompts.invoke.assert_not_called()


@pytest.mark.parametrize(
    "status,expected",
    [("inconclusive", "incomplete"), ("ok", "complete"), (None, "complete")],
)
def test_cli_reports_the_deduplication_outcome(status, expected):
    progress = Mock()
    reporter = ReviewCodeProgressReporter(progress)

    reporter(
        {
            "event": "findings_finalization_done",
            "status": status,
            "deduped_findings": 2,
            "removed_findings": 0,
            "raw_findings": 2,
        }
    )

    assert f"Dedup {expected}:" in progress.update.call_args.kwargs["description"]
