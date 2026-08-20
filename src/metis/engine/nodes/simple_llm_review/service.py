# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from typing import TYPE_CHECKING

import unidiff
from pydantic import ValidationError

from metis import runlog
from metis.engine.execution.contracts import NodeJobs
from metis.engine.llm_runner import ModelProviderConfigurationError
from metis.engine.stages.review.checkpoints import ReviewCheckpointSession
from metis.utils import read_file_content

from metis.engine.diff_utils import process_diff_file
from metis.engine.nodes.reachability.progress import emit_progress
from metis.engine.helpers import apply_custom_guidance, summarize_changes
from metis.engine.repository import EngineRepository
from metis.engine.runtime import EngineConfig
from metis.engine.threat_context_retrieval import get_threat_model_context

from metis.engine.stages.review.models import PatchReviewResult
from metis.engine.stages.review.models import ReviewCommand, ReviewRequest
from metis.engine.stages.review.models import ReviewDiagnostic
from metis.engine.stages.review.models import ReviewGroup
from metis.engine.stages.review.models import ReviewResult
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import ReviewStatus
from metis.engine.stages.review.models import StandardReviewResult
from metis.engine.stages.review.scope import select_review_targets

logger = logging.getLogger("metis")

if TYPE_CHECKING:
    from metis.engine.capabilities.index import IndexCapability
    from metis.memory import MemoryService


@dataclass(frozen=True, slots=True)
class ReviewFileFailure:
    path: str
    message: str


@dataclass(frozen=True, slots=True)
class TraditionalReviewOutcome:
    result: dict[str, Any]
    failures: tuple[ReviewFileFailure, ...]
    completed_files: int


class SimpleLlmReviewService:
    def __init__(
        self,
        config: EngineConfig,
        repository: EngineRepository,
        review_graph_factory: Callable[[IndexCapability | None, str | None], Any],
    ) -> None:
        self._config = config
        self._repository = repository
        self._review_graph_factory = review_graph_factory

    def run_review(
        self,
        command: ReviewCommand,
        *,
        jobs: NodeJobs,
        model: str | None = None,
        memory_service: MemoryService | None = None,
        index: IndexCapability | None = None,
        progress_callback: Callable[[dict[str, object]], None] | None = None,
        checkpoint_session: ReviewCheckpointSession | None = None,
    ) -> ReviewRun:
        if command.mode == "patch":
            review_graph = self._review_graph_factory(index, model)
            result = PatchReviewResult.model_validate(
                self.review_patch(
                    command.target,
                    model=model,
                    memory_service=memory_service,
                    review_graph=review_graph,
                    checkpoint_session=checkpoint_session,
                )
            )
            return _review_run(result)

        files = select_review_targets(self._repository, command)
        emit_progress(
            progress_callback,
            "review_files_start",
            total=len(files),
        )
        return self.run_files(
            files,
            jobs=jobs,
            model=model,
            memory_service=memory_service,
            index=index,
            progress_callback=progress_callback,
            checkpoint_session=checkpoint_session,
        )

    def run_files(
        self,
        files: tuple[str, ...],
        *,
        jobs: NodeJobs,
        model: str | None = None,
        memory_service: MemoryService | None = None,
        index: IndexCapability | None = None,
        progress_callback: Callable[[dict[str, object]], None] | None = None,
        checkpoint_session: ReviewCheckpointSession | None = None,
    ) -> ReviewRun:
        return self._run_traditional_review(
            files,
            progress_callback,
            jobs=jobs,
            memory_service=memory_service,
            review_graph=self._review_graph_factory(index, model),
            checkpoint_session=checkpoint_session,
        )

    def _run_traditional_review(
        self,
        files: tuple[str, ...],
        progress_callback,
        *,
        jobs: NodeJobs,
        memory_service: MemoryService | None,
        review_graph: Any,
        checkpoint_session: ReviewCheckpointSession | None,
    ) -> ReviewRun:
        outcome = self.execute_standard_review_with_outcome(
            files,
            jobs=jobs,
            progress_callback=progress_callback,
            memory_service=memory_service,
            review_graph=review_graph,
            checkpoint_session=checkpoint_session,
        )
        diagnostics = tuple(
            ReviewDiagnostic(
                code="review.file_failed",
                message=f"Review failed for {failure.path}: {failure.message}",
            )
            for failure in outcome.failures
        )
        if outcome.failures and not outcome.completed_files:
            return ReviewRun(
                status=ReviewStatus.FAILED,
                result=None,
                diagnostics=diagnostics,
            )
        status = (
            ReviewStatus.INCONCLUSIVE if outcome.failures else ReviewStatus.SUCCEEDED
        )
        result = StandardReviewResult.model_validate(outcome.result)
        return _review_run(result, status=status, diagnostics=diagnostics)

    def execute_standard_review_with_outcome(
        self,
        files,
        *,
        jobs: NodeJobs,
        progress_callback=None,
        memory_service: MemoryService | None = None,
        review_graph: Any | None = None,
        checkpoint_session: ReviewCheckpointSession | None = None,
    ) -> TraditionalReviewOutcome:
        review_graph = review_graph or self._review_graph_factory(None, None)
        selected_files: list[str] = list(files)
        remaining_files = selected_files
        reviews_by_path: dict[str, dict[str, Any]] = {}
        failures_by_path: dict[str, ReviewFileFailure] = {}
        completed_files = 0

        if checkpoint_session is not None and checkpoint_session.has_records:

            def load_cached(path: str) -> tuple[str, dict[str, Any] | None]:
                try:
                    review = self._review_file_standard(
                        path,
                        memory_service=memory_service,
                        review_graph=review_graph,
                        checkpoint_session=checkpoint_session,
                        cache_only=True,
                    )
                except Exception:
                    review = None
                return path, review

            cached_by_path = {
                path: review
                for path, review in jobs.run(
                    selected_files,
                    load_cached,
                    label="Load review checkpoint",
                    result_key=str,
                )
                if review is not None
            }
            if cached_by_path:
                remaining_files = [
                    path for path in selected_files if path not in cached_by_path
                ]
                reviews_by_path.update(cached_by_path)
                completed_files = len(cached_by_path)
                emit_progress(
                    progress_callback,
                    "review_result",
                    completed=completed_files,
                    total=len(selected_files),
                    resumed=completed_files,
                )

        def report_completion(_path: str, completed: int, _total: int) -> None:
            emit_progress(
                progress_callback,
                "review_result",
                completed=completed_files + completed,
                total=len(selected_files),
                resumed=completed_files,
            )

        for path, result, error in self._review_files(
            remaining_files,
            lambda path: self._review_file_standard(
                path,
                memory_service=memory_service,
                review_graph=review_graph,
                checkpoint_session=checkpoint_session,
            ),
            jobs,
            on_complete=report_completion,
        ):
            if error is not None:
                logger.error(f"Error reviewing file {path}: {error}")
                failures_by_path[path] = ReviewFileFailure(
                    path=str(path),
                    message=str(error),
                )
            else:
                completed_files += 1
                if result:
                    reviews_by_path[path] = result
        return TraditionalReviewOutcome(
            result={
                "reviews": [
                    reviews_by_path[path]
                    for path in selected_files
                    if path in reviews_by_path
                ]
            },
            failures=tuple(
                failures_by_path[path]
                for path in selected_files
                if path in failures_by_path
            ),
            completed_files=completed_files,
        )

    def _review_file_standard(
        self,
        file_path: str,
        *,
        memory_service: MemoryService | None = None,
        review_graph: Any | None = None,
        checkpoint_session: ReviewCheckpointSession | None = None,
        cache_only: bool = False,
    ) -> dict[str, Any] | None:
        base_path = os.path.abspath(self._config.codebase_path)
        snippet = read_file_content(file_path)
        if not snippet:
            return None

        plugin = self._repository.get_plugin_for_path(file_path)
        if not plugin:
            return None

        language_prompts = plugin.get_prompts()
        relative_path = os.path.relpath(file_path, base_path)
        threat_model_context = get_threat_model_context(
            memory_service,
            path=relative_path,
        )

        req: ReviewRequest = {
            "file_path": file_path,
            "snippet": snippet,
            "language_prompts": language_prompts,
            "default_prompt_key": "security_review_file",
            "relative_file": relative_path,
            "mode": "file",
            "threat_model_context": threat_model_context,
        }
        graph = review_graph or self._review_graph_factory(None, None)
        checkpoint_key = (
            graph.checkpoint_key(req) if checkpoint_session is not None else None
        )
        if checkpoint_key is not None and checkpoint_session is not None:
            cached = checkpoint_session.get(f"file:{checkpoint_key}")
            if cached is not None:
                try:
                    group = ReviewGroup.model_validate(cached)
                except ValidationError:
                    pass
                else:
                    return _review_group_payload(
                        group,
                        relative_path=relative_path,
                        file_path=file_path,
                    )
        if cache_only:
            return None

        result = graph.review(req)
        if result:
            group = ReviewGroup.model_validate(result)
            result = _review_group_payload(
                group,
                relative_path=relative_path,
                file_path=file_path,
            )
        if checkpoint_key is not None and checkpoint_session is not None and result:
            checkpoint_session.put(
                f"file:{checkpoint_key}",
                {
                    "reviews": [
                        review.model_dump(mode="json") for review in group.reviews
                    ]
                },
            )
        return result

    def _review_file_task(self, review_fn, path):
        with runlog.span(
            "task",
            "review_file",
            {"kind": "review_file", "file_path": str(path)},
        ) as task_span:
            runlog.bump("tasks")
            result = review_fn(path)
            task_span.end(attributes={"result": result})
            return result

    def _review_files(
        self,
        files,
        review_fn,
        jobs: NodeJobs,
        *,
        on_complete: Callable[[Any, int, int], None] | None = None,
    ):
        def review(path):
            try:
                return path, self._review_file_task(review_fn, path), None
            except ModelProviderConfigurationError:
                raise
            except Exception as exc:
                return path, None, exc

        return jobs.run(
            files,
            review,
            label=None,
            result_key=str,
            on_complete=on_complete,
        )

    def review_patch(
        self,
        patch_file,
        *,
        model: str | None = None,
        memory_service: MemoryService | None = None,
        review_graph: Any | None = None,
        checkpoint_session: ReviewCheckpointSession | None = None,
    ):
        patch_text = read_file_content(patch_file)
        try:
            diff = unidiff.PatchSet.from_string(patch_text)
            logger.info("Parsed the patch file successfully.")
        except Exception as e:
            logger.error(f"Error parsing patch file: {e}")
            return {"reviews": [], "overall_changes": ""}
        file_reviews = []
        overall_summaries = []
        base_path = os.path.abspath(self._config.codebase_path)
        metisignore_spec = self._repository.load_metisignore()
        graph = review_graph or self._review_graph_factory(None, model)
        for file_diff in diff:
            if file_diff.is_removed_file or file_diff.is_binary_file:
                continue
            abs_path = (
                file_diff.path
                if os.path.isabs(file_diff.path)
                else os.path.join(base_path, file_diff.path)
            )
            relative_path = self._repository.normalize_match_path(abs_path)
            if self._repository.is_metisignored(abs_path, spec=metisignore_spec):
                continue
            plugin = self._repository.get_plugin_for_path(file_diff.path)
            if not plugin:
                continue
            snippet = process_diff_file(file_diff)
            if not snippet:
                continue
            language_prompts = plugin.get_prompts()
            threat_model_context = get_threat_model_context(
                memory_service,
                path=relative_path,
            )
            try:
                original_content = read_file_content(abs_path)
            except Exception as exc:
                logger.error(f"Error processing review for {file_diff.path}: {exc}")
                continue
            req: ReviewRequest = {
                "file_path": abs_path,
                "snippet": snippet,
                "language_prompts": language_prompts,
                "default_prompt_key": "security_review",
                "relative_file": relative_path,
                "mode": "patch",
                "original_file": original_content or "",
                "threat_model_context": threat_model_context,
            }
            checkpoint_key = (
                graph.checkpoint_key(req) if checkpoint_session is not None else None
            )
            cached = (
                checkpoint_session.get(f"patch-file:{checkpoint_key}")
                if checkpoint_key is not None and checkpoint_session is not None
                else None
            )
            review_dict: dict[str, Any] | None = None
            changes_summary: str | None = None
            if cached is not None:
                try:
                    if "review" not in cached or "summary" not in cached:
                        raise ValueError("incomplete patch checkpoint record")
                    cached_review = cached["review"]
                    cached_summary = cached["summary"]
                    if cached_review is not None:
                        group = ReviewGroup.model_validate(cached_review)
                        review_dict = _review_group_payload(
                            group,
                            relative_path=relative_path,
                            file_path=abs_path,
                        )
                    if cached_summary is not None and not isinstance(
                        cached_summary, str
                    ):
                        raise ValueError("invalid patch checkpoint summary")
                    changes_summary = cached_summary
                except ValueError:
                    cached = None
                else:
                    assert checkpoint_session is not None

            if cached is None:
                checkpoint_group: ReviewGroup | None = None
                try:
                    review_dict = graph.review(req)
                except ModelProviderConfigurationError:
                    raise
                except Exception as exc:
                    logger.error(f"Error processing review for {file_diff.path}: {exc}")
                    continue
                if review_dict:
                    checkpoint_group = ReviewGroup.model_validate(review_dict)
                    review_dict = _review_group_payload(
                        checkpoint_group,
                        relative_path=relative_path,
                        file_path=abs_path,
                    )
                    issues = "\n".join(
                        issue.get("issue", "")
                        for issue in review_dict.get("reviews", [])
                    )
                    if issues.strip():
                        summary_prompt = language_prompts["snippet_security_summary"]
                        summary_prompt = apply_custom_guidance(
                            summary_prompt,
                            self._config.custom_prompt_text,
                            self._config.custom_guidance_precedence,
                        )
                        changes_summary = summarize_changes(
                            self._config.llm_provider,
                            file_diff.path,
                            issues,
                            summary_prompt,
                            model=model or self._config.llama_query_model,
                            chat_model_kwargs=self._config.chat_model_kwargs,
                            callbacks=self._config.usage_runtime.hooks.callbacks,
                        )
                if checkpoint_key is not None and checkpoint_session is not None:
                    checkpoint_session.put(
                        f"patch-file:{checkpoint_key}",
                        {
                            "review": (
                                {
                                    "reviews": [
                                        review.model_dump(mode="json")
                                        for review in checkpoint_group.reviews
                                    ]
                                }
                                if checkpoint_group is not None
                                else None
                            ),
                            "summary": changes_summary,
                        },
                    )

            if review_dict:
                file_reviews.append(review_dict)
            if changes_summary:
                overall_summaries.append(changes_summary)
        overall_changes = "\n\n".join(overall_summaries)
        return {"reviews": file_reviews, "overall_changes": overall_changes}


def _review_group_payload(
    group: ReviewGroup,
    *,
    relative_path: str,
    file_path: str,
) -> dict[str, Any]:
    return {
        "file": relative_path,
        "file_path": file_path,
        "reviews": [review.model_dump(mode="python") for review in group.reviews],
    }


def _review_run(
    result: ReviewResult,
    *,
    status: ReviewStatus = ReviewStatus.SUCCEEDED,
    diagnostics=(),
) -> ReviewRun:
    return ReviewRun(
        status=status,
        result=result,
        diagnostics=tuple(diagnostics),
    )
