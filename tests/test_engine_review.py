# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import Mock

from metis.engine import MetisEngine
from metis.engine.codegraph import CodeGraph
from metis.engine.llm_runner import JsonPromptRequest
from metis.engine.nodes.reachability.domain import FrontierReviewFailure
from metis.engine.nodes.reachability.domain import ReachabilityAnalysis
from metis.engine.nodes.reachability.review import ReachabilityReviewService
from metis.engine.nodes.simple_llm_review.service import SimpleLlmReviewService
from metis.engine.nodes.simple_llm_review.service import TraditionalReviewOutcome
from metis.engine.stages.review.models import ReviewCommand
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import ReviewStatus
from metis.engine.stages.review.models import StandardReviewResult


def _simple_llm_review(engine: MetisEngine) -> SimpleLlmReviewService:
    return SimpleLlmReviewService(
        engine._config,
        engine.repository,
        lambda index: engine._get_review_graph(index),
    )


def _prompt_json_section(request: JsonPromptRequest, label: str) -> Any:
    body = request.variables["body_text"]
    assert isinstance(body, str)
    marker = f"{label} (untrusted JSON):\n"
    _prefix, separator, remainder = body.partition(marker)
    assert separator
    value, _end = json.JSONDecoder().raw_decode(remainder)
    return value


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
        return_value=(
            [{"file": "supported.c", "reviews": [{"issue": "reachable"}]}],
            ReachabilityAnalysis(findings=()),
        )
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
    fallback.run_files.assert_called_once_with(
        (python_file,),
        memory_service=None,
        index=None,
        progress_callback=None,
    )
    assert "using simple LLM review fallback" in caplog.text


def test_reachability_does_not_run_simple_review_for_supported_files(engine):
    events = []
    simple = Mock(spec=SimpleLlmReviewService)
    simple.run_files.side_effect = AssertionError(
        "supported files must not use simple review"
    )
    service = ReachabilityReviewService(
        engine._config,
        engine.repository,
        Mock(),
        simple,
        {},
    )
    target = str(Path(engine.codebase_path) / "supported.c")
    service.supports_file = Mock(return_value=True)
    service.file_review = Mock(
        side_effect=lambda *_args, **_kwargs: (
            events.append("graph")
            or (
                {"file": "supported.c", "reviews": []},
                ReachabilityAnalysis(findings=()),
            )
        )
    )
    run = service.run_review(
        ReviewCommand(mode="file", target=target),
        codegraph=CodeGraph(),
    )

    assert run.status is ReviewStatus.SUCCEEDED
    assert events == ["graph"]
    simple.run_files.assert_not_called()
    assert "candidate_node_names" not in service.file_review.call_args.kwargs


def test_reachability_missing_graph_coverage_is_inconclusive(engine):
    service = ReachabilityReviewService(
        engine._config,
        engine.repository,
        Mock(),
        Mock(spec=SimpleLlmReviewService),
        {},
    )
    target = str(Path(engine.codebase_path) / "supported.c")
    service.supports_file = Mock(return_value=True)
    service.file_review = Mock(
        return_value=(
            {"file": "supported.c", "reviews": []},
            ReachabilityAnalysis(
                findings=(),
                codegraph_failures=(
                    "codegraph.target_missing:supported.c",
                    "codegraph.target_missing:supported.c",
                ),
            ),
        )
    )

    run = service.run_review(
        ReviewCommand(mode="file", target=target),
        codegraph=CodeGraph(),
    )

    assert run.status is ReviewStatus.INCONCLUSIVE
    assert run.diagnostics[0].code == "review.frontier_analysis_partial"
    assert "1 selected target" in run.diagnostics[0].message


def test_reachability_operational_failure_detail_survives_product_boundary(engine):
    service = ReachabilityReviewService(
        engine._config,
        engine.repository,
        Mock(),
        Mock(spec=SimpleLlmReviewService),
        {},
    )
    target = str(Path(engine.codebase_path) / "supported.c")
    service.supports_file = Mock(return_value=True)
    service.file_review = Mock(
        return_value=(
            {"file": "supported.c", "reviews": []},
            ReachabilityAnalysis(
                findings=(),
                review_failures=(
                    FrontierReviewFailure(
                        function_id="supported.c::reviewed",
                        kind="invalid_output",
                    ),
                ),
            ),
        )
    )

    run = service.run_review(
        ReviewCommand(mode="file", target=target),
        codegraph=CodeGraph(),
    )

    assert run.status is ReviewStatus.INCONCLUSIVE
    assert [diagnostic.code for diagnostic in run.diagnostics] == [
        "review.frontier_failure.discovery.invalid_output",
    ]


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
    assert run.diagnostics == ()


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
