# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
from pathlib import Path
from unittest.mock import Mock

import pytest

from metis.engine import MetisEngine
from metis.engine.codegraph import CodeGraph
from metis.engine.nodes.reachability.aggregation import ReviewResultAggregator
from metis.engine.nodes.reachability.validation import (
    parse_review_validation_response,
    rescue_filtered_duplicate_cluster_representatives,
    review_validation_final_keep,
)
from metis.engine.nodes.reachability.review import ReachabilityReviewService
from metis.engine.stages.review.models import ReviewCommand
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import ReviewStatus
from metis.engine.stages.review.models import StandardReviewResult
from metis.engine.nodes.simple_llm_review.service import SimpleLlmReviewService
from metis.engine.nodes.simple_llm_review.service import TraditionalReviewOutcome


def _simple_llm_review(engine: MetisEngine) -> SimpleLlmReviewService:
    return SimpleLlmReviewService(
        engine._config,
        engine.repository,
        lambda index: engine._get_review_graph(index),
    )


def test_ask_question(engine):
    result = engine.ask_question("What is this?")
    assert "code" in result
    assert "docs" in result


def test_simple_llm_review_processes_the_selected_scope(engine):
    service = _simple_llm_review(engine)
    files = (
        str(Path(engine.codebase_path) / "supported.c"),
        str(Path(engine.codebase_path) / "baseline.py"),
    )
    service._repository.get_code_files = Mock(return_value=list(files))
    service.execute_standard_review_with_outcome = Mock(
        return_value=TraditionalReviewOutcome(
            result={"reviews": []},
            failures=(),
            completed_files=2,
        )
    )

    run = service.run_review(ReviewCommand(mode="code"))

    assert run.status is ReviewStatus.SUCCEEDED
    assert run.diagnostics == ()
    assert service.execute_standard_review_with_outcome.call_args.args == (files,)


def test_patch_review_uses_simple_llm_review(engine):
    service = _simple_llm_review(engine)
    service.review_patch = Mock(
        return_value={
            "reviews": [],
            "overall_changes": "No security-relevant change.",
        }
    )

    run = service.run_review(
        ReviewCommand(mode="patch", target="change.patch"),
    )

    assert run.status is ReviewStatus.SUCCEEDED
    assert run.result is not None
    assert run.result.overall_changes == "No security-relevant change."
    service.review_patch.assert_called_once_with(
        "change.patch",
        memory_service=None,
        review_graph=engine._get_review_graph(),
    )


def test_reachability_review_falls_back_for_unsupported_files(engine, caplog):
    fallback = Mock(spec=SimpleLlmReviewService)
    fallback.run_files.return_value = ReviewRun(
        ReviewStatus.SUCCEEDED,
        StandardReviewResult.model_validate(
            {"reviews": [{"file": "baseline.py", "reviews": [{"issue": "fallback"}]}]}
        ),
    )
    service = ReachabilityReviewService(
        engine._config,
        engine.repository,
        Mock(),
        fallback,
        {},
    )
    c_file = str(Path(engine.codebase_path) / "supported.c")
    python_file = str(Path(engine.codebase_path) / "baseline.py")
    service._repository.get_code_files = Mock(return_value=[c_file, python_file])
    service.supports_file = Mock(side_effect=lambda path: path.endswith(".c"))
    service.codebase_reviews = Mock(
        return_value=[{"file": "supported.c", "reviews": [{"issue": "reachable"}]}]
    )
    service.aggregate_results = Mock(
        return_value={
            "reviews": [{"file": "supported.c", "reviews": [{"issue": "reachable"}]}]
        }
    )

    with caplog.at_level(
        logging.DEBUG,
        logger="metis.engine.nodes.reachability.review",
    ):
        run = service.run_review(
            ReviewCommand(mode="code"),
            codegraph=CodeGraph(),
        )

    assert run.status is ReviewStatus.SUCCEEDED
    assert run.result is not None
    assert [
        finding.issue for group in run.result.reviews for finding in group.reviews
    ] == ["reachable", "fallback"]
    assert run.diagnostics == ()
    assert service.codebase_reviews.call_args.kwargs["files"] == (c_file,)
    assert service.aggregate_results.call_args.kwargs["deduplicate"] is False
    fallback.run_files.assert_called_once_with(
        (python_file,),
        memory_service=None,
        index=None,
        progress_callback=None,
    )
    assert "using simple LLM review fallback" in caplog.text


def test_file_review_aggregation_consolidates_before_validation(engine):
    duplicate = {
        "issue": "unchecked chunk length",
        "primary_file": "pngrutil.c",
        "primary_function": "png_handle_chunk",
        "line_number": 42,
        "analysis_type": "reachability",
        "severity": "High",
        "confidence": 0.9,
    }
    adjudicator = Mock(
        return_value={
            "groups": [
                {
                    "relationship": "duplicate",
                    "member_indexes": [0, 1],
                    "representative_index": 0,
                }
            ]
        }
    )
    aggregator = ReviewResultAggregator(
        engine._config,
        {},
        final_adjudicator=adjudicator,
    )
    aggregator._validator.validate_candidates = Mock(
        return_value=[
            {
                "index": 0,
                "keep": True,
                "confidence": 0.9,
                "reason": "reachable from parsed input",
            }
        ]
    )

    result = aggregator.aggregate(
        {
            "reviews": [
                {"file": "pngread.c", "reviews": [duplicate, {"issue": "general"}]},
                {"file": "pngrutil.c", "reviews": [dict(duplicate)]},
            ]
        }
    )

    review_items = [item for group in result["reviews"] for item in group["reviews"]]
    assert [item["issue"] for item in review_items] == [
        "unchecked chunk length",
        "general",
    ]
    assert result["review_validation_summary"]["total_candidates"] == 1
    aggregator._validator.validate_candidates.assert_called_once()
    adjudicator.assert_called_once()


def test_reachability_codebase_review_confirms_default_paths(engine):
    service = ReachabilityReviewService(
        engine._config,
        engine.repository,
        Mock(),
        Mock(spec=SimpleLlmReviewService),
        {"max_paths": 0},
    )

    options = service.review_options(settings={"max_paths": 0}, codebase=True)

    assert options.confirm_paths is True


def test_reachability_review_rejects_symlink_outside_codebase(engine, tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("secret = True\n", encoding="utf-8")
    target = Path(engine.codebase_path) / "outside.py"
    target.symlink_to(outside)
    fallback = Mock(spec=SimpleLlmReviewService)
    service = ReachabilityReviewService(
        engine._config,
        engine.repository,
        Mock(),
        fallback,
        {},
    )

    run = service.run_review(
        ReviewCommand(mode="file", target=str(target)),
        codegraph=CodeGraph(),
    )

    assert run.status is ReviewStatus.INCONCLUSIVE
    assert run.diagnostics[0].code == "review.target_outside_codebase"
    fallback.run_files.assert_not_called()


def test_reachability_defers_fallback_to_explicit_simple_review(engine):
    service = ReachabilityReviewService(
        engine._config,
        engine.repository,
        Mock(),
        None,
        {},
    )
    python_file = str(Path(engine.codebase_path) / "baseline.py")
    service._repository.get_code_files = Mock(return_value=[python_file])
    service.supports_file = Mock(return_value=False)

    run = service.run_review(ReviewCommand(mode="code"), codegraph=CodeGraph())

    assert run.status is ReviewStatus.SUCCEEDED
    assert run.result is not None
    assert run.result.reviews == []


def test_reachability_empty_scope_is_inconclusive(engine):
    service = ReachabilityReviewService(
        engine._config,
        engine.repository,
        Mock(),
        Mock(spec=SimpleLlmReviewService),
        {},
    )
    service._repository.get_code_files = Mock(return_value=[])

    run = service.run_review(ReviewCommand(mode="code"), codegraph=CodeGraph())

    assert run.status is ReviewStatus.INCONCLUSIVE


def test_review_validation_rescues_duplicate_cluster_representative():
    candidates = [
        {
            "index": 0,
            "issue": "queue use after free",
            "primary_file": "driver.c",
            "primary_function": "delete_queue",
            "line_number": 42,
            "severity": "High",
            "confidence": 0.9,
            "cwe": "CWE-416",
        },
        {
            "index": 1,
            "issue": "queue callback use after free",
            "primary_file": "driver.c",
            "primary_function": "delete_queue",
            "line_number": 42,
            "severity": "High",
            "confidence": 0.85,
            "cwe": "CWE-416",
        },
    ]
    decisions = [
        {
            "index": 0,
            "keep": False,
            "confidence": 0.4,
            "drop_reason": "duplicate",
            "reason": "duplicate of stronger candidate",
        },
        {
            "index": 1,
            "keep": False,
            "confidence": 0.5,
            "drop_reason": "duplicate",
            "reason": "same root cause duplicate",
        },
    ]

    kept = [
        decision
        for decision in rescue_filtered_duplicate_cluster_representatives(
            candidates, decisions
        )
        if decision["keep"]
    ]

    assert len(kept) == 1
    assert kept[0]["index"] == 0
    assert kept[0]["confidence"] >= 0.9
    assert "strongest representative" in kept[0]["reason"]


@pytest.mark.parametrize(
    ("candidate", "decision", "expected"),
    [
        (
            {
                "issue": "Unchecked addition can wrap the page count before indexing an array",
                "severity": "High",
                "confidence": 0.75,
                "root_cause": "integer overflow in page range calculation",
                "evidence": "nr_pages = offset + size",
            },
            {
                "index": 0,
                "keep": False,
                "confidence": 0.42,
                "reason": "Security impact is not fully established.",
            },
            True,
        ),
        (
            {
                "issue": "Unchecked addition can wrap before indexing an array",
                "severity": "High",
                "confidence": 0.95,
                "root_cause": "integer overflow in page range calculation",
                "evidence": "nr_pages = offset + size",
            },
            {
                "index": 0,
                "keep": False,
                "confidence": 0.2,
                "drop_reason": "false_positive",
                "reason": "The value is already bounds-checked before use.",
            },
            False,
        ),
    ],
)
def test_review_validation_guardrails(candidate, decision, expected):
    assert review_validation_final_keep(candidate, decision) is expected


def test_review_validation_parser_accepts_double_encoded_json():
    parsed = parse_review_validation_response(
        '"{\\"decisions\\":[{\\"index\\":0,\\"keep\\":true,'
        '\\"confidence\\":0.82,\\"drop_reason\\":\\"\\",\\"reason\\":\\"ok\\"}]}"'
    )
    assert parsed == {
        "decisions": [
            {
                "index": 0,
                "keep": True,
                "confidence": 0.82,
                "drop_reason": "",
                "reason": "ok",
            }
        ]
    }


class _DummyReviewGraph:
    def __init__(self, review):
        self._review = review

    def review(self, req):
        if self._review is None:
            return {"file": "test.py", "reviews": []}
        return self._review


def test_review_patch_parses_and_reviews(engine, monkeypatch, tmp_path):
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(
        "--- a/test.py\n+++ b/test.py\n@@ -0,0 +1,2 @@\n+print('Hello')\n+print('World')\n"
    )
    monkeypatch.setattr(
        engine,
        "_get_review_graph",
        lambda _index=None: _DummyReviewGraph(
            {"file": "test.py", "reviews": [{"issue": "Issue"}]}
        ),
    )

    import metis.engine.nodes.simple_llm_review.service as review_service_mod

    monkeypatch.setattr(
        review_service_mod, "summarize_changes", lambda *a, **k: "summary"
    )

    result = _simple_llm_review(engine).review_patch(str(patch_file))
    assert "reviews" in result and isinstance(result["reviews"], list)
    assert any(r.get("file") == "test.py" for r in result["reviews"])


def test_review_patch_handles_parse_error(engine, tmp_path):
    bad_patch_file = tmp_path / "bad.diff"
    bad_patch_file.write_text("INVALID PATCH FORMAT")
    result = _simple_llm_review(engine).review_patch(str(bad_patch_file))
    assert "reviews" in result
    assert result["reviews"] == []
