# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from metis.cli.review_checkpoints import review_checkpoint_callbacks
from metis.engine import MetisEngine
from metis.engine.codegraph import CodeGraph
from metis.engine.execution.contracts import NodeCallbacks
from metis.engine.llm_runner import JsonPromptRequest
from metis.engine.llm_runner import ModelProviderConfigurationError
from metis.engine.nodes.reachability.domain import FrontierReviewFailure
from metis.engine.nodes.reachability.domain import ReachabilityAnalysis
from metis.engine.nodes.reachability.review import ReachabilityReviewService
from metis.engine.nodes.simple_llm_review.service import SimpleLlmReviewService
from metis.engine.nodes.simple_llm_review.service import TraditionalReviewOutcome
from metis.engine.stages.review.checkpoints import ReviewCheckpointSession
from metis.engine.stages.review.models import ReviewCommand
from metis.engine.stages.review.models import ReviewCheckpointRecord
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import ReviewStatus
from metis.engine.stages.review.models import StandardReviewResult
from metis.version import __version__ as METIS_VERSION


def _simple_llm_review(engine: MetisEngine) -> SimpleLlmReviewService:
    return SimpleLlmReviewService(
        engine._config,
        engine.repository,
        lambda index, model: engine._get_review_graph(index, model),
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

    run = service.run_review(
        ReviewCommand(mode="code"),
        jobs=engine.execution._jobs,
    )

    assert run.status is ReviewStatus.SUCCEEDED
    assert run.diagnostics == ()
    assert service.execute_standard_review_with_outcome.call_args.args == (files,)


def test_simple_review_stops_scheduling_after_provider_configuration_failure(
    engine,
):
    service = _simple_llm_review(engine)
    files = tuple(f"file-{index}.c" for index in range(20))
    calls: list[str] = []

    def fail(path: str) -> None:
        calls.append(path)
        raise ModelProviderConfigurationError("bad certificate")

    with pytest.raises(ModelProviderConfigurationError, match="bad certificate"):
        service._review_files(files, fail, engine.execution._jobs)

    assert 0 < len(calls) <= engine._config.max_workers


def test_simple_review_orders_results_by_selected_file(engine):
    files = tuple(
        str(Path(engine.codebase_path) / name) for name in ("first.c", "second.c")
    )
    for path in files:
        Path(path).write_text("int value;\n", encoding="utf-8")
    graph = Mock()
    graph.review.side_effect = lambda request: {
        "reviews": [{"issue": request["relative_file"]}]
    }
    service = SimpleLlmReviewService(
        engine._config,
        engine.repository,
        lambda _index, _model: graph,
    )

    class ReverseJobs:
        def run(self, jobs, worker, **_kwargs):
            return [worker(job) for job in reversed(jobs)]

    review = service.run_files(files, jobs=ReverseJobs())

    assert review.result is not None
    assert [group.model_dump()["file"] for group in review.result.reviews] == [
        "first.c",
        "second.c",
    ]


def test_simple_llm_review_resumes_completed_files(engine, tmp_path):
    target = Path(engine.codebase_path) / "supported.c"
    target.write_text("int original(void) { return 0; }\n", encoding="utf-8")
    graph = Mock()
    graph.checkpoint_key.side_effect = lambda request: request["snippet"]
    graph.review.return_value = {
        "file": "supported.c",
        "file_path": str(target),
        "reviews": [{"issue": "cached finding"}],
    }
    service = SimpleLlmReviewService(
        engine._config,
        engine.repository,
        lambda _index, _model: graph,
    )
    callbacks = review_checkpoint_callbacks(
        codebase_path=tmp_path,
        enabled=True,
    )
    node_callbacks = NodeCallbacks(
        checkpoint=callbacks["review_checkpoint_callback"],
        resume=callbacks["review_resume_callback"],
    )
    callbacks["review_checkpoint_callback"](
        ReviewCheckpointRecord(
            metis_version=METIS_VERSION,
            producer="simple_llm_review",
            key=f"file:{target.read_text(encoding='utf-8')}",
            record={"reviews": "invalid"},
        ).model_dump(mode="json"),
        1,
        1,
    )

    first_session = ReviewCheckpointSession(
        "simple_llm_review",
        node_callbacks,
    )
    first = service.run_files(
        (str(target),),
        jobs=engine.execution._jobs,
        checkpoint_session=first_session,
    )
    progress_events = []
    second = service.run_files(
        (str(target),),
        jobs=engine.execution._jobs,
        progress_callback=progress_events.append,
        checkpoint_session=ReviewCheckpointSession(
            "simple_llm_review",
            node_callbacks,
        ),
    )

    assert first.result == second.result
    graph.review.assert_called_once()
    assert progress_events[-1] == {
        "event": "review_result",
        "completed": 1,
        "total": 1,
        "resumed": 1,
    }

    fresh_target = Path(engine.codebase_path) / "fresh.c"
    fresh_target.write_text("int fresh(void) { return 1; }\n", encoding="utf-8")
    progress_events.clear()
    service.run_files(
        (str(target), str(fresh_target)),
        jobs=engine.execution._jobs,
        progress_callback=progress_events.append,
        checkpoint_session=ReviewCheckpointSession(
            "simple_llm_review",
            node_callbacks,
        ),
    )

    assert progress_events[0] == {
        "event": "review_result",
        "completed": 1,
        "total": 2,
        "resumed": 1,
    }
    assert progress_events[-1] == {
        "event": "review_result",
        "completed": 2,
        "total": 2,
        "resumed": 1,
    }
    assert graph.review.call_count == 2
    assert graph.review.call_args.args[0]["file_path"] == str(fresh_target)

    target.write_text("int changed(void) { return 1; }\n", encoding="utf-8")
    service.run_files(
        (str(target),),
        jobs=engine.execution._jobs,
        checkpoint_session=ReviewCheckpointSession(
            "simple_llm_review",
            node_callbacks,
        ),
    )

    assert graph.review.call_count == 3


def test_review_checkpoint_callback_failures_are_best_effort():
    session = ReviewCheckpointSession(
        "simple_llm_review",
        NodeCallbacks(
            checkpoint=Mock(side_effect=RuntimeError("write failed")),
            resume=Mock(side_effect=RuntimeError("read failed")),
        ),
    )

    session.put("file:key", {"reviews": []})

    assert session.get("file:key") == {"reviews": []}


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
        jobs=engine.execution._jobs,
    )

    assert run.status is ReviewStatus.SUCCEEDED
    assert run.result is not None
    assert run.result.overall_changes == "No security-relevant change."
    service.review_patch.assert_called_once_with(
        "change.patch",
        model=None,
        memory_service=None,
        review_graph=engine._get_review_graph(),
        checkpoint_session=None,
    )


def test_patch_review_resumes_completed_files(engine, tmp_path, monkeypatch):
    target = Path(engine.codebase_path) / "target.c"
    target.write_text("int value = 1;\n", encoding="utf-8")
    patch = tmp_path / "change.patch"
    patch.write_text(
        "--- a/target.c\n"
        "+++ b/target.c\n"
        "@@ -1 +1 @@\n"
        "-int value = 0;\n"
        "+int value = 1;\n",
        encoding="utf-8",
    )
    graph = Mock()
    graph.checkpoint_key.side_effect = lambda request: request["snippet"]
    graph.review.return_value = {
        "file": "target.c",
        "file_path": str(target),
        "reviews": [{"issue": "patch finding"}],
    }
    summarize = Mock(return_value="patch summary")
    monkeypatch.setattr(
        "metis.engine.nodes.simple_llm_review.service.summarize_changes",
        summarize,
    )
    service = SimpleLlmReviewService(
        engine._config,
        engine.repository,
        lambda _index, _model: graph,
    )
    callbacks = review_checkpoint_callbacks(
        codebase_path=tmp_path,
        enabled=True,
    )
    node_callbacks = NodeCallbacks(
        checkpoint=callbacks["review_checkpoint_callback"],
        resume=callbacks["review_resume_callback"],
    )

    first = service.review_patch(
        str(patch),
        review_graph=graph,
        checkpoint_session=ReviewCheckpointSession(
            "simple_llm_review",
            node_callbacks,
        ),
    )
    second = service.review_patch(
        str(patch),
        review_graph=graph,
        checkpoint_session=ReviewCheckpointSession(
            "simple_llm_review",
            node_callbacks,
        ),
    )

    assert first == second
    graph.review.assert_called_once()
    summarize.assert_called_once()

    graph.review.side_effect = ModelProviderConfigurationError("bad certificate")
    with pytest.raises(ModelProviderConfigurationError, match="bad certificate"):
        service.review_patch(str(patch), review_graph=graph)


def test_reachability_review_falls_back_for_unsupported_files(engine, caplog):
    progress_events: list[dict[str, object]] = []
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
            jobs=engine.execution._jobs,
            codegraph=CodeGraph(),
            progress_callback=progress_events.append,
        )

    assert run.status is ReviewStatus.SUCCEEDED
    assert run.result is not None
    assert [
        finding.issue for group in run.result.reviews for finding in group.reviews
    ] == ["reachable", "fallback"]
    assert run.diagnostics == ()
    assert service.codebase_reviews.call_args.kwargs["files"] == (c_file,)
    assert progress_events[:3] == [
        {
            "event": "reachability_phase_progress",
            "phase": "scope",
            "completed": 0,
            "total": 2,
        },
        {
            "event": "reachability_phase_progress",
            "phase": "scope",
            "completed": 1,
            "total": 2,
        },
        {
            "event": "reachability_phase_progress",
            "phase": "scope",
            "completed": 2,
            "total": 2,
        },
    ]
    fallback.run_files.assert_called_once_with(
        (python_file,),
        jobs=engine.execution._jobs,
        model=None,
        memory_service=None,
        index=None,
        progress_callback=progress_events.append,
        checkpoint_session=None,
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
        jobs=engine.execution._jobs,
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
        jobs=engine.execution._jobs,
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
        jobs=engine.execution._jobs,
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
        jobs=engine.execution._jobs,
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

    run = service.run_review(
        ReviewCommand(mode="code"),
        jobs=engine.execution._jobs,
        codegraph=CodeGraph(),
    )

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

    run = service.run_review(
        ReviewCommand(mode="code"),
        jobs=engine.execution._jobs,
        codegraph=CodeGraph(),
    )

    assert run.status is ReviewStatus.INCONCLUSIVE


class _DummyReviewGraph:
    def __init__(self, review):
        self._review = review
        self.requests = []

    def review(self, req):
        self.requests.append(req)
        if self._review is None:
            return {"file": "test.py", "reviews": []}
        return self._review


def test_review_patch_parses_and_reviews(engine, monkeypatch, tmp_path):
    (Path(engine.codebase_path) / "test.py").write_text(
        "print('Old')\n",
        encoding="utf-8",
    )
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(
        "--- a/test.py\n+++ b/test.py\n@@ -1 +1 @@\n-print('Old')\n+print('New')\n"
    )
    review_graph = _DummyReviewGraph(
        {"file": "test.py", "reviews": [{"issue": "Issue"}]}
    )
    monkeypatch.setattr(
        engine,
        "_get_review_graph",
        lambda _index=None, _model=None: review_graph,
    )

    import metis.engine.nodes.simple_llm_review.service as review_service_mod

    monkeypatch.setattr(
        review_service_mod, "summarize_changes", lambda *a, **k: "summary"
    )

    result = _simple_llm_review(engine).review_patch(str(patch_file))
    assert "reviews" in result and isinstance(result["reviews"], list)
    assert any(r.get("file") == "test.py" for r in result["reviews"])
    (request,) = review_graph.requests
    assert request["mode"] == "patch"
    assert request["original_file"] == "print('Old')\n"
    assert request["snippet"] == "-print('Old')\n+print('New')\n"


def test_review_patch_handles_parse_error(engine, tmp_path):
    bad_patch_file = tmp_path / "bad.diff"
    bad_patch_file.write_text("INVALID PATCH FORMAT")
    result = _simple_llm_review(engine).review_patch(str(bad_patch_file))
    assert "reviews" in result
    assert result["reviews"] == []
