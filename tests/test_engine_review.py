# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import os
import subprocess
from concurrent.futures import CancelledError
from hashlib import sha256
from pathlib import Path
from threading import Barrier
from typing import Any
from unittest.mock import Mock

import pytest
from unidiff.errors import UnidiffParseError

from metis.cli.review_checkpoints import review_checkpoint_callbacks
from metis.cli.review_checkpoints import stage_checkpoint_callback
from metis.cli.utils import save_output
from metis.engine import ExecutionGraphError
from metis.engine import MetisEngine
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import FunctionNode
from metis.engine.execution.contracts import NodeCallbacks
from metis.engine.execution import ExecutionResult
from metis.engine.execution import ExecutionStatus
from metis.engine.llm_runner import JsonPromptRequest
from metis.engine.llm_runner import ModelProviderConfigurationError
from metis.engine.llm_runner import rendered_prompt_token_count
from metis.engine.model_tool_runner import ModelInputLimitError
from metis.engine.nodes.reachability.domain import FrontierReviewFailure
from metis.engine.nodes.reachability.domain import ReachabilityAnalysis
from metis.engine.nodes.reachability.review import ReachabilityReviewService
from metis.engine.nodes.simple_llm_review.service import SimpleLlmReviewService
from metis.engine.nodes.simple_llm_review.service import TraditionalReviewOutcome
from metis.engine.source import ProfiledSourceArtifact
from metis.engine.source import ProfiledSourceReference
from metis.engine.source import SourceMap
from metis.engine.stages.review.checkpoints import ReviewCheckpointSession
from metis.engine.stages.review.models import ReviewCheckpointRecord
from metis.engine.stages.review.models import ReviewCommand
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import ReviewStatus
from metis.engine.stages.review.models import StandardReviewResult
from metis.sarif.triage import TRIAGE_ANNOTATION_KEYS
from metis.version import __version__ as METIS_VERSION


def _simple_llm_review(engine: MetisEngine) -> SimpleLlmReviewService:
    return SimpleLlmReviewService(
        engine._config,
        engine.repository,
        engine._get_review_graph,
    )


def _covered_graph(path: str) -> CodeGraph:
    graph = CodeGraph()
    graph.add_node(FunctionNode(f"{path}::entry", path, "entry", 1))
    return graph


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


def test_default_language_review_uses_navigation(engine):
    source = Path(engine.codebase_path) / "main.r"
    source.write_text("guard()\n", encoding="utf-8")
    (source.parent / "guard.txt").write_text("guard evidence\n", encoding="utf-8")
    navigation = engine.capabilities["navigation"]
    graph = engine._get_review_graph(navigation=navigation)
    graph.max_token_length = 20_000

    def respond(request):
        tool = next(tool for tool in request.model_tools if tool.name == "sed")
        assert "guard evidence" in tool.invoke(
            {"path": "guard.txt", "start_line": 1, "end_line": 1}
        )
        return [{"issue": "Check guard", "code_snippet": "guard()"}]

    graph._prompt_runner.invoke = Mock(side_effect=respond)
    run = _simple_llm_review(engine).run_review(
        ReviewCommand(mode="file", target=str(source)),
        jobs=engine.execution._jobs,
        navigation=navigation,
    )
    assert run.status is ReviewStatus.SUCCEEDED
    assert run.result.reviews[0].file == "main.r"
    graph._prompt_runner.invoke.assert_called_once()


@pytest.mark.parametrize("failure", ["first", "second", "cancelled"])
def test_simple_review_stops_scheduling_and_retains_completed_results(
    tmp_path, dummy_llm, capability_settings, failure
):
    files = [tmp_path / f"file-{index}.c" for index in range(3)]
    for path in files:
        path.write_text("int unchecked;\n", encoding="utf-8")
    engine = MetisEngine(
        codebase_path=str(tmp_path),
        llm_provider=dummy_llm,
        max_workers=1,
        max_token_length=20_000,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        capability_settings=capability_settings,
        execution_config={
            "inputs": {"review_request": {"mode": "code"}},
            "stages": {
                "review": {
                    "nodes": {
                        "simple_llm_review": {},
                        "finding_dedup": {},
                        "result": {},
                    }
                }
            },
        },
    )
    engine.repository.get_code_files = Mock(return_value=list(map(str, files)))
    graph = engine._get_review_graph()
    error = (
        CancelledError("cancelled")
        if failure == "cancelled"
        else ModelProviderConfigurationError("bad certificate")
    )
    completed = [] if failure == "first" else [{"reviews": [{"issue": "Check input"}]}]
    graph.review = Mock(side_effect=[*completed, error])
    try:
        if failure == "cancelled":
            with pytest.raises(CancelledError):
                engine.execute_review("code")
        else:
            with pytest.raises(ExecutionGraphError, match="bad certificate") as caught:
                engine.execute_review("code")
            if completed:
                output = caught.value.result.outputs["review"]
                assert [group["file"] for group in output["findings"]["reviews"]] == [
                    files[0].name
                ]
                assert len(output["sarif"]["runs"][0]["results"]) == 1
            else:
                assert not caught.value.result.outputs
        assert graph.review.call_count == len(completed) + 1
    finally:
        engine.close()


def test_simple_review_orders_results_by_selected_file(engine):
    files = tuple(
        str(Path(engine.codebase_path) / name) for name in ("first.c", "second.c")
    )
    for path in files:
        Path(path).write_text("int value;\n", encoding="utf-8")
    graph = Mock()
    graph.review.side_effect = lambda request, **_kwargs: {
        "reviews": [{"issue": request["relative_file"]}]
    }
    service = SimpleLlmReviewService(
        engine._config,
        engine.repository,
        lambda _index, _model: graph,
    )

    class ReverseJobs:
        def with_cancellation(self, _cancellation):
            return self

        def run(self, jobs, worker, **_kwargs):
            return [worker(job) for job in reversed(jobs)]

    review = service.run_files(files, jobs=ReverseJobs())

    assert review.result is not None
    assert [group.model_dump()["file"] for group in review.result.reviews] == [
        "first.c",
        "second.c",
    ]
    assert all(
        "anchor_source_hash" not in call.args[0] for call in graph.review.call_args_list
    )


def test_simple_review_uses_profile_bytes_and_anchors_raw_source(engine) -> None:
    raw = (
        b"int marker; /* \xff\f */\n"
        b"void active(void) {\n    risky();\n    inactive_bug();\n}\n"
    )
    canonical = raw.replace(b"    inactive_bug();", b"                   ")
    assert len(raw) == len(canonical)
    target = Path(engine.codebase_path) / "profiled.c"
    target.write_bytes(raw)
    engine.repository.install_profiled_source(
        ProfiledSourceArtifact(
            reference=ProfiledSourceReference(
                fingerprint="review-profile",
                compile_commands_path="compile_commands.json",
                compile_commands_sha256="0" * 64,
                translation_units=1,
                source_views=1,
                profiled_files=1,
                ambiguous_files=0,
                active_line_count=3,
            ),
            languages=frozenset({"c", "cpp"}),
            raw_sources={target.name: raw},
            canonical_sources={target.name: canonical},
        )
    )
    graph = engine._get_review_graph(None, None)
    graph.max_token_length = 20_000

    def model_response(request):
        body = request.variables["body_text"]
        assert "risky();" in body
        assert "3:     risky();" in body
        assert "inactive_bug();" not in body
        return request.parse(
            {
                "reviews": [
                    {
                        "issue": "Active issue",
                        "code_snippet": "risky();\n\n}",
                        "start_line": 2,
                        "end_line": 4,
                        "reasoning": "Active path reaches risky operation.",
                        "mitigation": "Validate input first.",
                        "confidence": 0.9,
                        "cwe": "CWE-20",
                        "severity": "HIGH",
                    }
                ]
            }
        )

    graph._prompt_runner.invoke = Mock(side_effect=model_response)
    service = _simple_llm_review(engine)
    checkpoint_session = Mock(has_records=False)
    checkpoint_session.get.return_value = None
    run = service.run_files(
        (str(target),),
        jobs=engine.execution._jobs,
        checkpoint_session=checkpoint_session,
    )

    assert run.status is ReviewStatus.SUCCEEDED
    assert run.result is not None
    finding = run.result.reviews[0].reviews[0].model_dump()
    raw_anchor = SourceMap.for_bytes(target.name, raw).anchor_for_lines(3, 5)
    canonical_anchor = SourceMap.for_bytes(target.name, canonical).anchor_for_lines(
        3, 5
    )
    assert finding["anchor"] == raw_anchor.to_dict()
    assert finding["anchor"]["start_byte"] == raw.index(b"    risky();")
    assert finding["anchor"]["symbol"] == "profiled.c::active"
    assert finding["anchor"]["content_hash"] != canonical_anchor.content_hash
    assert json.dumps(checkpoint_session.put.call_args.args[1])

    other = Path(engine.codebase_path) / "other.py"
    other.write_text("print('unchanged')\n", encoding="utf-8")
    plugin = engine.repository.get_plugin_for_path(str(target))
    language_for_path = engine.repository.get_language_name_for_path
    engine.repository.get_plugin_for_path = lambda _path: plugin
    engine.repository.get_language_name_for_path = lambda path: (
        "python" if path == str(other) else language_for_path(path)
    )
    other_graph = Mock()
    other_graph.review.return_value = None
    service._review_file_standard(str(other), review_graph=other_graph)
    other_request = other_graph.review.call_args.args[0]
    assert other_request["snippet"] == "print('unchanged')\n"
    assert "anchor_source_hash" not in other_request

    review = graph.review

    def change_source(request, **kwargs):
        target.write_text("void changed(void) {}\n", encoding="utf-8")
        return review(request, **kwargs)

    graph.review = change_source
    failed = service.run_files((str(target),), jobs=engine.execution._jobs)

    assert failed.status is ReviewStatus.FAILED
    assert "Source changed during review" in failed.diagnostics[0].message
    graph._prompt_runner.invoke.assert_called_once()


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
        failures=[],
        emit=None,
        on_summary=None,
        summary_input=None,
    )


@pytest.mark.parametrize("failure_kind", ["source", "model", "configuration"])
def test_patch_review_retains_completed_files_after_failure(
    engine, tmp_path, monkeypatch, failure_kind
):
    patch = tmp_path / "changes.patch"
    names = ("first.c", "second.c", "third.c")
    patch.write_text(
        "".join(
            f"--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n-int old;\n+int active;\n"
            for name in names
        )
    )
    for name in names:
        (Path(engine.codebase_path) / name).write_text("int active;\n")
    graph = Mock()
    issue = {"reviews": [{"issue": "Check active"}]}
    if failure_kind == "source":
        (Path(engine.codebase_path) / "second.c").write_bytes(b"\xff")
        graph.review.return_value = issue
    else:
        error = (
            ModelProviderConfigurationError
            if failure_kind == "configuration"
            else RuntimeError
        )
        graph.review.side_effect = [issue, error("review failed"), issue]
    monkeypatch.setattr(
        "metis.engine.nodes.simple_llm_review.service.summarize_changes",
        lambda *args, **kwargs: "Completed summary",
    )
    service = SimpleLlmReviewService(
        engine._config, engine.repository, lambda *args: graph
    )

    run = service.run_review(
        ReviewCommand(mode="patch", target=str(patch)), jobs=engine.execution._jobs
    )

    assert run.status is ReviewStatus.INCONCLUSIVE
    assert run.result is not None
    expected_names = (
        ["first.c"] if failure_kind == "configuration" else ["first.c", "third.c"]
    )
    assert [group.file for group in run.result.reviews] == expected_names
    assert run.result.overall_changes == "\n\n".join(
        "Completed summary" for _ in expected_names
    )
    assert len(run.diagnostics) == 1
    assert run.diagnostics[0].code == "review.file_failed"
    assert "second.c" in run.diagnostics[0].message


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
    navigation = engine.capabilities["navigation"]
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
        supports_file=lambda path: path.endswith(".c"),
    )
    c_file = str(Path(engine.codebase_path) / "supported.c")
    python_file = str(Path(engine.codebase_path) / "baseline.py")
    service._repository.get_code_files = Mock(return_value=[c_file, python_file])
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
            codegraph=_covered_graph("supported.c"),
            navigation=navigation,
            progress_callback=progress_events.append,
        )

    assert run.status is ReviewStatus.SUCCEEDED
    assert run.result is not None
    assert [
        finding.issue for group in run.result.reviews for finding in group.reviews
    ] == ["reachable", "fallback"]
    assert run.diagnostics == ()
    assert service.codebase_reviews.call_args.kwargs["files"] == (c_file,)
    assert service.codebase_reviews.call_args.kwargs["navigation"] is navigation
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
        navigation=navigation,
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
        supports_file=lambda _path: True,
    )
    target = str(Path(engine.codebase_path) / "supported.c")
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
        codegraph=_covered_graph("supported.c"),
    )

    assert run.status is ReviewStatus.SUCCEEDED
    assert events == ["graph"]
    simple.run_files.assert_not_called()
    assert "candidate_node_names" not in service.file_review.call_args.kwargs


def test_reachability_operational_failure_detail_survives_product_boundary(engine):
    service = ReachabilityReviewService(
        engine._config,
        engine.repository,
        Mock(),
        Mock(spec=SimpleLlmReviewService),
        {},
        supports_file=lambda _path: True,
    )
    target = str(Path(engine.codebase_path) / "supported.c")
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
        codegraph=_covered_graph("supported.c"),
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
        supports_file=lambda _path: False,
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
        supports_file=lambda _path: False,
    )
    python_file = str(Path(engine.codebase_path) / "baseline.py")
    service._repository.get_code_files = Mock(return_value=[python_file])
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
        supports_file=lambda _path: False,
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

    def review(self, req, *, collect_navigation_evidence=False):
        self.requests.append(req)
        if self._review is None:
            return {"file": "test.py", "reviews": []}
        return self._review


@pytest.mark.parametrize(
    "filename", ["café.c", "tab\tname.c", "../café.c", "~sample.c", "~/name.c"]
)
def test_patch_review_decodes_git_quoted_paths(engine, tmp_path, filename):
    root = Path(engine.codebase_path)
    target = root / filename
    before = root / "before" / target.name
    before.parent.mkdir()
    before.write_text("int func(void) { return 0; }\n", encoding="utf-8")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("int func(void) { return 1; }\n", encoding="utf-8")
    completed = subprocess.run(
        [
            "git",
            "-c",
            "core.quotePath=true",
            "diff",
            "--no-index",
            "--",
            str(before.relative_to(root)),
            os.path.relpath(target, root),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 1, completed.stderr
    patch = tmp_path / "quoted.diff"
    patch.write_text(completed.stdout, encoding="utf-8")
    graph = _DummyReviewGraph(None)
    service = _simple_llm_review(engine)
    if filename.startswith("../"):
        with pytest.raises(ValueError, match="escapes codebase"):
            service.review_patch(str(patch), review_graph=graph)
        assert graph.requests == []
        return

    result = service.review_patch(str(patch), review_graph=graph)

    assert result["reviews"][0]["file"] == filename
    (request,) = graph.requests
    assert request["file_path"] == str(target)
    assert request["original_file"] == target.read_text(encoding="utf-8")


@pytest.mark.parametrize("parent_alias", [False, True])
def test_review_patch_parses_and_reviews(engine, monkeypatch, tmp_path, parent_alias):
    root = Path(engine.codebase_path)
    source = root / "test.py"
    patch_path = "test.py"
    if parent_alias:
        (root / "src" / "nested").mkdir(parents=True)
        (root / "alias").symlink_to(root / "src" / "nested", target_is_directory=True)
        source.write_text("wrong_file\n", encoding="utf-8")
        source = root / "src" / "test.py"
        patch_path = "alias/../test.py"
    source.write_text(
        "print('Old')\n",
        encoding="utf-8",
    )
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(
        f"--- a/{patch_path}\n+++ b/{patch_path}\n@@ -1,1 +1,1 @@\n-print('Old')\n+print('New')\n"
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
    assert result["reviews"][0]["file"] == source.relative_to(root).as_posix()
    (request,) = review_graph.requests
    assert request["file_path"] == str(source)
    assert request["mode"] == "patch"
    assert request["original_file"] == "print('Old')\n"
    assert request["snippet"] == patch_file.read_text()

    review_graph.review = Mock(side_effect=ModelInputLimitError("input too large"))
    with pytest.raises(ModelInputLimitError, match="input too large"):
        _simple_llm_review(engine).review_patch(str(patch_file))

    review_graph.review.side_effect = RuntimeError("invalid review")
    with pytest.raises(RuntimeError, match="invalid review"):
        _simple_llm_review(engine).review_patch(str(patch_file))

    review_graph.review.side_effect = CancelledError()
    with pytest.raises(CancelledError):
        _simple_llm_review(engine).run_review(
            ReviewCommand(mode="patch", target=str(patch_file)),
            jobs=engine.execution._jobs,
        )

    source.write_bytes(b"\xff")
    with pytest.raises(UnicodeDecodeError):
        _simple_llm_review(engine).review_patch(str(patch_file))

    failed = _simple_llm_review(engine).run_review(
        ReviewCommand(mode="patch", target=str(patch_file)),
        jobs=engine.execution._jobs,
    )
    assert failed.status is ReviewStatus.FAILED
    assert failed.result is None
    assert failed.diagnostics[0].code == "review.file_failed"


@pytest.mark.parametrize(
    "patch_text",
    [
        "INVALID PATCH FORMAT",
        "--- a/test.c\n+++ b/test.c\n@@ -1 +1 @@\n-int old;\n",
    ],
)
def test_review_patch_rejects_invalid_patch(engine, tmp_path, patch_text):
    bad_patch_file = tmp_path / "bad.diff"
    bad_patch_file.write_text(patch_text, encoding="utf-8")

    with pytest.raises(
        (ValueError, UnidiffParseError), match="(no file changes|Hunk is shorter)"
    ):
        _simple_llm_review(engine).review_patch(str(bad_patch_file))


def test_simple_review_receives_granted_navigation(engine):
    target = Path(engine.codebase_path) / "caller.c"
    target.write_text(
        "int value;\n" * 99 + "void caller(void) { guard(); }\n", encoding="utf-8"
    )
    helper = Path(engine.codebase_path) / "guard.c"
    helper.write_text("void guard(void) {}\n", encoding="utf-8")
    navigation = engine.capabilities["navigation"]
    engine._config.llm_provider.count_tokens = lambda text, **_: (
        len(text) + text.count("  ")
    )
    graph = engine._get_review_graph(navigation=navigation)
    graph.max_token_length = 20_000
    prompt_sizes = []

    def respond(request):
        prompt_sizes.append(
            rendered_prompt_token_count(
                graph._token_counter,
                system_prompt=request.system_prompt,
                user_prompt=request.user_prompt,
                variables=request.variables,
                model_tools=request.model_tools,
            )
        )
        assert prompt_sizes[-1] <= graph.max_token_length
        tools = {tool.name: tool for tool in request.model_tools}
        assert request.max_tool_rounds == 6
        assert "void guard(void)" in tools["sed"].invoke(
            {"path": "guard.c", "start_line": 1, "end_line": 1}
        )
        return []

    graph._prompt_runner.invoke = Mock(side_effect=respond)
    run = _simple_llm_review(engine).run_review(
        ReviewCommand(mode="file", target=str(target)),
        jobs=engine.execution._jobs,
        navigation=navigation,
    )

    assert run.status is ReviewStatus.SUCCEEDED
    graph._prompt_runner.invoke.assert_called_once()
    assert run.result is not None
    assert run.result.reviews[0].reviews == []

    graph.max_token_length = prompt_sizes[0] - 1
    graph._prompt_runner.invoke.reset_mock()
    run = _simple_llm_review(engine).run_review(
        ReviewCommand(mode="file", target=str(target)),
        jobs=engine.execution._jobs,
        navigation=navigation,
    )
    assert run.status is ReviewStatus.SUCCEEDED
    assert graph._prompt_runner.invoke.call_count > 1


@pytest.mark.parametrize(
    ("operation", "mode", "relocated_state"),
    [
        ("sed", "file", False),
        ("grep", "file", True),
        ("find_name", "file", False),
        ("grep", "patch", False),
        ("find_name", "file", True),
    ],
)
def test_navigation_review_replays_evidence_before_resume(
    engine, tmp_path, monkeypatch, operation, mode, relocated_state
):
    target = Path(engine.codebase_path) / "caller.c"
    target.write_text("void caller(void) { guard(); }\n", encoding="utf-8")
    helper = Path(engine.codebase_path) / "ignored" / "guard.c"
    helper.parent.mkdir()
    helper.write_text("void guard(void) {}\n", encoding="utf-8")
    (Path(engine.codebase_path) / ".gitignore").write_text("ignored/\n")
    if relocated_state:
        state_path = Path(engine.codebase_path) / "private" / "cache"
        state_path.mkdir(parents=True)
        (Path(engine.codebase_path) / ".metis").symlink_to(
            state_path, target_is_directory=True
        )
        (Path(engine.codebase_path) / "state-alias").symlink_to(
            state_path, target_is_directory=True
        )
    navigation = engine.capabilities["navigation"]
    graph = engine._get_review_graph(navigation=navigation)
    graph.max_token_length = 20_000
    arguments = {
        "sed": {"path": "ignored/guard.c", "start_line": 1, "end_line": 1},
        "grep": {"pattern": "guard", "path": "."},
        "find_name": {"name": "guard.c"},
    }[operation]

    def respond(request):
        tools = {tool.name: tool for tool in request.model_tools}
        output = str(tools[operation].invoke(arguments))
        request.on_tool_result(operation, arguments, output)
        return [{"issue": "guard needs checking", "code_snippet": "guard();"}]

    graph._prompt_runner.invoke = Mock(side_effect=respond)
    replay = Mock(wraps=graph.checkpoint_evidence_valid)
    monkeypatch.setattr(graph, "checkpoint_evidence_valid", replay)
    monkeypatch.setattr(
        "metis.engine.nodes.simple_llm_review.service.summarize_changes",
        Mock(return_value="guard summary"),
    )
    callbacks = review_checkpoint_callbacks(
        codebase_path=engine.codebase_path, enabled=True
    )
    node_callbacks = NodeCallbacks(
        checkpoint=callbacks["review_checkpoint_callback"],
        resume=callbacks["review_resume_callback"],
    )
    command_target = target
    if mode == "patch":
        command_target = tmp_path / "caller.patch"
        command_target.write_text(
            "--- a/caller.c\n+++ b/caller.c\n@@ -1 +1 @@\n"
            "-void caller(void) {}\n+void caller(void) { guard(); }\n",
            encoding="utf-8",
        )

    def review():
        run = _simple_llm_review(engine).run_review(
            ReviewCommand(mode=mode, target=str(command_target)),
            jobs=engine.execution._jobs,
            navigation=navigation,
            checkpoint_session=ReviewCheckpointSession(
                "simple_llm_review", node_callbacks
            ),
        )
        stage_checkpoint_callback(codebase_path=engine.codebase_path)(
            ExecutionResult(
                ExecutionStatus.OK,
                {"review": {"findings": run.result.model_dump(mode="json")}},
            )
        )
        if operation == "grep":
            root = Path(engine.codebase_path)
            save_output(
                [root / "review.json", root / "review.sarif"],
                run.result.model_dump(mode="json"),
                quiet=True,
                codebase_path=root,
            )
        return run

    first = review()
    second = review()
    assert first.status is second.status is ReviewStatus.SUCCEEDED
    assert first.result == second.result
    for run in (first, second):
        assert all(
            "navigation_evidence" not in group
            for group in run.result.model_dump()["reviews"]
        )
    graph._prompt_runner.invoke.assert_called_once()

    if operation == "find_name":
        added = helper.parent / "new" / "guard.c"
        added.parent.mkdir()
        added.write_text("void another_guard(void) {}\n", encoding="utf-8")
    else:
        helper.write_text("void guard(void) { abort(); }\n", encoding="utf-8")
    replay.reset_mock()
    assert review().status is ReviewStatus.SUCCEEDED
    assert graph._prompt_runner.invoke.call_count == 2
    replay.assert_called_once()

    helper.unlink()
    if operation == "sed":
        graph._prompt_runner.invoke.side_effect = lambda request: []
    assert review().status is ReviewStatus.SUCCEEDED
    assert graph._prompt_runner.invoke.call_count == 3


@pytest.mark.parametrize("mode", ["file", "patch"])
@pytest.mark.parametrize("invalid_review", [{}, {"reviews": None}, {"reviews": ""}])
def test_review_resume_requires_explicit_review_collection(
    engine, mode, invalid_review
):
    target = Path(engine.codebase_path) / "caller.c"
    target.write_text("int caller;\n")
    navigation = engine.capabilities["navigation"]
    graph = engine._get_review_graph(navigation=navigation)
    graph.max_token_length = 20_000
    graph._prompt_runner.invoke = Mock(return_value=[])
    if mode == "patch":
        target = target.with_suffix(".patch")
        target.write_text(
            "--- a/caller.c\n+++ b/caller.c\n@@ -1 +1 @@\n-int old;\n+int caller;\n"
        )
    records = {}
    callbacks = NodeCallbacks(
        checkpoint=lambda payload, *_: records.update(
            {payload["key"]: payload["record"]}
        ),
        resume=lambda _: records,
    )

    def review():
        return _simple_llm_review(engine).run_review(
            ReviewCommand(mode=mode, target=str(target)),
            jobs=engine.execution._jobs,
            navigation=navigation,
            checkpoint_session=ReviewCheckpointSession("simple_llm_review", callbacks),
        )

    assert review().status is ReviewStatus.SUCCEEDED
    record = next(iter(records.values()))
    if mode == "file":
        record.pop("reviews")
        record.update(invalid_review)
    else:
        record["review"] = invalid_review
    assert review().status is ReviewStatus.SUCCEEDED
    assert graph._prompt_runner.invoke.call_count == 2


@pytest.mark.parametrize("mode", ["file", "patch"])
def test_simple_review_checkpoint_cannot_mark_discovery_triaged(engine, mode):
    target = Path(engine.codebase_path) / "caller.c"
    target.write_text("int caller;\n")
    graph = engine._get_review_graph()
    graph.max_token_length = 20_000
    graph._prompt_runner.invoke = Mock(return_value=[{"issue": "Check caller"}])
    if mode == "patch":
        target = target.with_suffix(".patch")
        target.write_text(
            "--- a/caller.c\n+++ b/caller.c\n@@ -1 +1 @@\n-int old;\n+int caller;\n"
        )
    records = {}
    callbacks = NodeCallbacks(
        checkpoint=lambda payload, *_: records.update(
            {payload["key"]: payload["record"]}
        ),
        resume=lambda _: records,
    )

    def review():
        return _simple_llm_review(engine).run_review(
            ReviewCommand(mode=mode, target=str(target)),
            jobs=engine.execution._jobs,
            checkpoint_session=ReviewCheckpointSession("simple_llm_review", callbacks),
        )

    assert review().status is ReviewStatus.SUCCEEDED
    record = next(iter(records.values()))
    review_record = record if mode == "file" else record["review"]
    review_record["reviews"][0].update({key: True for key in TRIAGE_ANNOTATION_KEYS})
    review_record["reviews"][0]["customEvidence"] = "preserved"

    run = review()

    graph._prompt_runner.invoke.assert_called_once()
    finding = run.result.reviews[0].reviews[0].model_dump()
    assert not TRIAGE_ANNOTATION_KEYS.intersection(finding)
    assert finding["customEvidence"] == "preserved"


@pytest.mark.parametrize("mode", ("file", "patch"))
@pytest.mark.parametrize("case", ("disabled", "complete", "overflow", "tool_error"))
def test_navigation_checkpoints_bound_evidence_across_chunks(
    engine, tmp_path, monkeypatch, mode, case
):
    target = Path(engine.codebase_path) / "caller.c"
    source = "int first;\nint second;\nint third;\n"
    target.write_text(source, encoding="utf-8")
    helper = target.with_suffix(".txt")
    helper.write_text("supporting evidence\n", encoding="utf-8")
    navigation = engine.capabilities["navigation"]
    graph = engine._get_review_graph(navigation=navigation)
    graph.max_token_length = 20_000
    monkeypatch.setattr(
        "metis.engine.nodes.simple_llm_review.graph._MAX_CHECKPOINT_TOOL_OBSERVATIONS",
        2,
    )
    chunks = [(line, index) for index, line in enumerate(source.splitlines(True), 1)]
    monkeypatch.setattr(graph, "_chunks", lambda _snippet: chunks)
    calls = []
    arguments = {"path": helper.name}

    def respond(request):
        chunk = len(calls) % len(chunks)
        calls.append(request)
        tool = next(tool for tool in request.model_tools if tool.name == "cat")
        content = str(tool.invoke(arguments))
        disabled = (
            case == "disabled"
            or (case == "overflow" and chunk == 2)
            or (case == "tool_error" and chunk > 0)
        )
        if disabled:
            assert request.on_tool_result is request.on_tool_error is None
        elif case == "tool_error":
            request.on_tool_error()
        elif chunk < 2:
            request.on_tool_result("cat", arguments, content)
            if case == "overflow" and chunk == 1:
                request.on_tool_result("cat", arguments, content)
        return []

    graph._prompt_runner.invoke = Mock(side_effect=respond)
    session = (
        None
        if case == "disabled"
        else ReviewCheckpointSession("simple_llm_review", NodeCallbacks())
    )
    if mode == "patch":
        target = tmp_path / "caller.patch"
        target.write_text(
            "--- a/caller.c\n+++ b/caller.c\n@@ -1 +1,3 @@\n-int before;\n"
            + "".join(f"+{line}" for line in source.splitlines(True)),
            encoding="utf-8",
        )
    for _ in range(2):
        run = _simple_llm_review(engine).run_review(
            ReviewCommand(mode=mode, target=str(target)),
            jobs=engine.execution._jobs,
            navigation=navigation,
            checkpoint_session=session,
        )
        assert run.status is ReviewStatus.SUCCEEDED
        if session is not None:
            assert session.has_records == (case == "complete")
    assert len(calls) == len(chunks) * (1 if case == "complete" else 2)


def test_navigation_checkpoint_validates_records_and_propagates_cancel(
    engine, monkeypatch
):
    target = Path(engine.codebase_path) / "helper.c"
    target.write_text("int helper;\n", encoding="utf-8")
    navigation = engine.capabilities["navigation"]
    graph = engine._get_review_graph(navigation=navigation)
    observation = {
        "name": "sed",
        "arguments": {"path": "helper.c", "start_line": 1, "end_line": 1},
        "output_sha256": sha256(navigation.sed("helper.c", 1, 1).encode()).hexdigest(),
    }
    assert graph.checkpoint_evidence_valid({"navigation_evidence": [observation]})
    resolve_path = Mock(wraps=navigation._resolve_path)
    monkeypatch.setattr(navigation, "_resolve_path", resolve_path)
    for evidence in (
        None,
        [None],
        [{}],
        [{**observation, "name": "index_search"}],
        [observation] * 1025,
        [{**observation, "output_sha256": "z" * 64}],
        [{**observation, "output_sha256": "0" * 63}],
    ):
        assert not graph.checkpoint_evidence_valid({"navigation_evidence": evidence})
    resolve_path.assert_not_called()
    for arguments in (
        {"path": "../outside", "start_line": 1, "end_line": 1},
        {"path": "helper.c", "start_line": "1", "end_line": 1},
    ):
        assert not graph.checkpoint_evidence_valid(
            {"navigation_evidence": [{**observation, "arguments": arguments}]}
        )
    monkeypatch.setattr(navigation, "_resolve_path", Mock(side_effect=CancelledError()))
    with pytest.raises(CancelledError):
        graph.checkpoint_evidence_valid({"navigation_evidence": [observation]})


def test_navigation_checkpoint_key_tracks_tool_configuration(engine):
    navigation = engine.capabilities["navigation"]
    graph = engine._get_review_graph(navigation=navigation)
    request = {
        "file_path": str(Path(engine.codebase_path) / "caller.c"),
        "snippet": "int caller;",
        "language_prompts": {"security_review_file": "Review."},
    }
    original = graph.checkpoint_key(request)
    assert original is not None
    graph.model_tool_max_rounds += 1
    assert graph.checkpoint_key(request) != original
    graph.model_tool_max_rounds -= 1
    navigation.max_chars += 1
    assert graph.checkpoint_key(request) != original
    navigation.max_chars -= 1
    graph.model_tools[0].metadata["metis_contract"] += "Changed rule."
    assert graph.checkpoint_key(request) != original
    graph.model_tools += (Mock(name="index_search"),)
    assert graph.checkpoint_key(request) is None


def test_parallel_navigation_checkpoints_keep_each_files_evidence(engine):
    codebase = Path(engine.codebase_path)
    targets = tuple(codebase / name for name in ("first.c", "second.c"))
    for target in targets:
        target.write_text(f"int {target.stem};\n", encoding="utf-8")
        target.with_suffix(".txt").write_text(f"context for {target.stem}\n")
    navigation = engine.capabilities["navigation"]
    graph = engine._get_review_graph(navigation=navigation)
    graph.max_token_length = 20_000
    barrier = Barrier(2, timeout=5)
    synchronize = True

    def respond(request):
        body = request.variables["body_text"]
        filename = "first.txt" if "int first;" in body else "second.txt"
        arguments = {"path": filename}
        tool = next(tool for tool in request.model_tools if tool.name == "cat")
        if synchronize:
            barrier.wait()
        request.on_tool_result("cat", arguments, str(tool.invoke(arguments)))
        if synchronize:
            barrier.wait()
        return []

    graph._prompt_runner.invoke = Mock(side_effect=respond)
    session = ReviewCheckpointSession("simple_llm_review", NodeCallbacks())

    def review():
        return _simple_llm_review(engine).run_files(
            tuple(map(str, targets)),
            jobs=engine.execution._jobs,
            navigation=navigation,
            checkpoint_session=session,
        )

    assert review().status is ReviewStatus.SUCCEEDED
    assert graph._prompt_runner.invoke.call_count == 2
    synchronize = False
    assert review().status is ReviewStatus.SUCCEEDED
    assert graph._prompt_runner.invoke.call_count == 2
    (codebase / "first.txt").write_text("changed helper\n")
    assert review().status is ReviewStatus.SUCCEEDED
    assert graph._prompt_runner.invoke.call_count == 3
