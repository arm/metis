# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any
from typing import TYPE_CHECKING

import unidiff

from metis.usage import submit_with_current_context
from metis import runlog
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
        review_graph_factory: Callable[[IndexCapability | None], Any],
    ) -> None:
        self._config = config
        self._repository = repository
        self._review_graph_factory = review_graph_factory

    def run_review(
        self,
        command: ReviewCommand,
        *,
        memory_service: MemoryService | None = None,
        index: IndexCapability | None = None,
        progress_callback: Callable[[dict[str, object]], None] | None = None,
    ) -> ReviewRun:
        if command.mode == "patch":
            review_graph = self._review_graph_factory(index)
            result = PatchReviewResult.model_validate(
                self.review_patch(
                    command.target,
                    memory_service=memory_service,
                    review_graph=review_graph,
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
            memory_service=memory_service,
            index=index,
            progress_callback=progress_callback,
        )

    def run_files(
        self,
        files: tuple[str, ...],
        *,
        memory_service: MemoryService | None = None,
        index: IndexCapability | None = None,
        progress_callback: Callable[[dict[str, object]], None] | None = None,
    ) -> ReviewRun:
        return self._run_traditional_review(
            files,
            progress_callback,
            memory_service=memory_service,
            review_graph=self._review_graph_factory(index),
        )

    def _run_traditional_review(
        self,
        files: tuple[str, ...],
        progress_callback,
        *,
        memory_service: MemoryService | None,
        review_graph: Any,
    ) -> ReviewRun:
        outcome = self.execute_standard_review_with_outcome(
            files,
            progress_callback=progress_callback,
            memory_service=memory_service,
            review_graph=review_graph,
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
        progress_callback=None,
        memory_service: MemoryService | None = None,
        review_graph: Any | None = None,
    ) -> TraditionalReviewOutcome:
        review_graph = review_graph or self._review_graph_factory(None)
        selected_files = list(files)
        reviews = []
        failures = []
        completed_files = 0
        for path, result, error in self._review_files(
            selected_files,
            lambda path: self._review_file_standard(
                path,
                memory_service=memory_service,
                review_graph=review_graph,
            ),
        ):
            if error is not None:
                logger.error(f"Error reviewing file {path}: {error}")
                failures.append(ReviewFileFailure(path=str(path), message=str(error)))
            else:
                completed_files += 1
                if result:
                    reviews.append(result)
            emit_progress(progress_callback, "review_result")
        return TraditionalReviewOutcome(
            result={"reviews": reviews},
            failures=tuple(failures),
            completed_files=completed_files,
        )

    def _review_file_standard(
        self,
        file_path,
        *,
        memory_service: MemoryService | None = None,
        review_graph: Any | None = None,
    ):
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
        return (review_graph or self._review_graph_factory(None)).review(req)

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
    ):
        with ThreadPoolExecutor(max_workers=self._config.max_workers) as executor:
            future_to_path = {
                submit_with_current_context(
                    executor, self._review_file_task, review_fn, path
                ): path
                for path in files
            }
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    yield path, future.result(), None
                except Exception as exc:
                    yield path, None, exc

    def review_patch(
        self,
        patch_file,
        *,
        memory_service: MemoryService | None = None,
        review_graph: Any | None = None,
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
            snippet = process_diff_file(
                self._config.codebase_path,
                file_diff,
                self._config.max_token_length,
                token_counter=self._config.llm_provider.count_tokens,
            )
            if not snippet:
                continue
            language_prompts = plugin.get_prompts()
            threat_model_context = get_threat_model_context(
                memory_service,
                path=relative_path,
            )
            try:
                original_content = read_file_content(abs_path)
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
                review_dict = (review_graph or self._review_graph_factory(None)).review(
                    req
                )
            except Exception as e:
                logger.error(f"Error processing review for {file_diff.path}: {e}")
                review_dict = None
            if review_dict:
                file_reviews.append(review_dict)
                issues = "\n".join(
                    issue.get("issue", "") for issue in review_dict.get("reviews", [])
                )
                if not issues.strip():
                    continue
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
                    model=self._config.llama_query_model,
                    chat_model_kwargs=self._config.chat_model_kwargs,
                    callbacks=self._config.usage_runtime.hooks.callbacks,
                )
                if changes_summary:
                    overall_summaries.append(changes_summary)
        overall_changes = "\n\n".join(overall_summaries)
        return {"reviews": file_reviews, "overall_changes": overall_changes}


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
