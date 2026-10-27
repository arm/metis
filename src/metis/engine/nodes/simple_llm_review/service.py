# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from codecs import escape_decode
from concurrent.futures import CancelledError
from dataclasses import dataclass
from functools import partial
from hashlib import sha256
from pathlib import Path
from threading import Event
from threading import Lock
from typing import TYPE_CHECKING
from typing import Any

import unidiff
from pydantic import ValidationError

from metis import runlog
from metis.engine.execution.contracts import NodeJobs
from metis.engine.helpers import apply_custom_guidance
from metis.engine.helpers import summarize_changes
from metis.engine.llm_runner import ModelProviderConfigurationError
from metis.engine.nodes.simple_llm_review.prompt import normalize_review_fields
from metis.engine.nodes.reachability.progress import emit_progress
from metis.engine.repository import EngineRepository
from metis.engine.runtime import EngineConfig
from metis.engine.source import SourceMap
from metis.engine.stages.review.checkpoints import ReviewCheckpointSession
from metis.engine.stages.review.models import REVIEW_FILE_FAILED
from metis.engine.stages.review.models import PatchReviewResult
from metis.engine.stages.review.models import ReviewCommand
from metis.engine.stages.review.models import ReviewDiagnostic
from metis.engine.stages.review.models import ReviewGroup
from metis.engine.stages.review.models import ReviewRequest
from metis.engine.stages.review.models import ReviewResult
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import ReviewStatus
from metis.engine.stages.review.models import StandardReviewResult
from metis.engine.stages.review.scope import select_review_targets
from metis.engine.threat_context_retrieval import get_threat_model_context
from metis.utils import resolve_path_within_root

logger = logging.getLogger("metis")

if TYPE_CHECKING:
    from metis.engine.capabilities.index import IndexCapability
    from metis.engine.capabilities.navigation import NavigationCapability
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
        review_graph_factory: Callable[..., Any],
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
        navigation: NavigationCapability | None = None,
        progress_callback: Callable[[dict[str, object]], None] | None = None,
        checkpoint_session: ReviewCheckpointSession | None = None,
        emit=None,
        on_summary=None,
        summary_input=None,
        begin_patch_entry=None,
        files: tuple[str, ...] | None = None,
    ) -> ReviewRun:
        if command.mode == "patch":
            graph_kwargs = {"navigation": navigation} if navigation is not None else {}
            review_graph = self._review_graph_factory(index, model, **graph_kwargs)
            failures: list[ReviewFileFailure] = []
            emitted = False

            def emit_group(group):
                nonlocal emitted
                emit(group)
                emitted = True

            result = PatchReviewResult.model_validate(
                self.review_patch(
                    command.target,
                    model=model,
                    memory_service=memory_service,
                    review_graph=review_graph,
                    checkpoint_session=checkpoint_session,
                    failures=failures,
                    emit=emit_group if emit is not None else None,
                    on_summary=on_summary,
                    summary_input=summary_input,
                    **(
                        {"begin_patch_entry": begin_patch_entry}
                        if begin_patch_entry is not None
                        else {}
                    ),
                )
            )
            has_result = bool(result.reviews) or emitted
            return ReviewRun(
                status=(
                    ReviewStatus.INCONCLUSIVE if has_result else ReviewStatus.FAILED
                )
                if failures
                else ReviewStatus.SUCCEEDED,
                result=result if has_result or not failures else None,
                diagnostics=tuple(
                    ReviewDiagnostic(
                        code=REVIEW_FILE_FAILED,
                        message=f"Review failed for {failure.path}: {failure.message}",
                    )
                    for failure in failures
                ),
            )

        if files is None:
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
            navigation=navigation,
            progress_callback=progress_callback,
            checkpoint_session=checkpoint_session,
            emit=emit,
        )

    def run_files(
        self,
        files: tuple[str, ...],
        *,
        jobs: NodeJobs,
        model: str | None = None,
        memory_service: MemoryService | None = None,
        index: IndexCapability | None = None,
        navigation: NavigationCapability | None = None,
        progress_callback: Callable[[dict[str, object]], None] | None = None,
        checkpoint_session: ReviewCheckpointSession | None = None,
        emit=None,
    ) -> ReviewRun:
        graph_kwargs = {"navigation": navigation} if navigation is not None else {}
        return self._run_traditional_review(
            files,
            progress_callback,
            jobs=jobs,
            memory_service=memory_service,
            review_graph=self._review_graph_factory(index, model, **graph_kwargs),
            checkpoint_session=checkpoint_session,
            emit=emit,
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
        emit=None,
    ) -> ReviewRun:
        outcome = self.execute_standard_review_with_outcome(
            files,
            jobs=jobs,
            progress_callback=progress_callback,
            memory_service=memory_service,
            review_graph=review_graph,
            checkpoint_session=checkpoint_session,
            emit=emit,
        )
        diagnostics = tuple(
            ReviewDiagnostic(
                code=REVIEW_FILE_FAILED,
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
        emit=None,
    ) -> TraditionalReviewOutcome:
        review_graph = review_graph or self._review_graph_factory(None, None)
        selected_files: list[str] = list(files)
        remaining_files = selected_files
        reviews_by_path: dict[str, dict[str, Any]] = {}
        failures_by_path: dict[str, ReviewFileFailure] = {}
        completed_files = 0
        loaded_checkpoints = (
            checkpoint_session is not None and checkpoint_session.has_records
        )

        if loaded_checkpoints:

            def load_cached(path: str) -> tuple[str, dict[str, Any] | None]:
                try:
                    review = self._review_file_standard(
                        path,
                        memory_service=memory_service,
                        review_graph=review_graph,
                        checkpoint_session=checkpoint_session,
                        cache_only=True,
                    )
                except CancelledError:
                    raise
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

        resumed_files = completed_files

        def report_completion(_path: str, completed: int, _total: int) -> None:
            emit_progress(
                progress_callback,
                "review_result",
                completed=resumed_files + completed,
                total=len(selected_files),
                resumed=resumed_files,
            )

        review_file = partial(
            self._review_file_standard,
            memory_service=memory_service,
            review_graph=review_graph,
            checkpoint_session=checkpoint_session,
            load_checkpoint=not loaded_checkpoints,
            emit=emit,
        )
        result_lock = Lock()

        def review(path):
            nonlocal completed_files
            try:
                result = self._review_file_task(review_file, path)
            except CancelledError:
                raise
            except Exception as exc:
                logger.error(f"Error reviewing file {path}: {exc}")
                with result_lock:
                    failures_by_path[path] = ReviewFileFailure(
                        path=str(path), message=str(exc)
                    )
                if isinstance(exc, ModelProviderConfigurationError):
                    raise
            else:
                with result_lock:
                    completed_files += 1
                    if result:
                        reviews_by_path[path] = result

        try:
            jobs.with_cancellation(Event()).run(
                remaining_files,
                review,
                label=None,
                result_key=str,
                on_complete=report_completion,
            )
        except ModelProviderConfigurationError:
            pass
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
        load_checkpoint: bool = True,
        emit=None,
    ) -> dict[str, Any] | None:
        source_path = resolve_path_within_root(
            self._config.codebase_path, file_path, preserve_aliases=True
        )
        file_path = str(source_path)
        source_view = self._repository.source_view_for_path(file_path)
        if source_view is None:
            snippet = source_path.read_text(encoding="utf-8")
            anchor_source_hash = None
        else:
            snippet = source_view.canonical.decode("utf-8", errors="ignore")
            anchor_source_hash = sha256(source_view.raw).hexdigest()
        if not snippet.strip():
            return None

        plugin = self._repository.get_plugin_for_path(file_path)
        if not plugin:
            return None

        language_prompts = plugin.get_prompts()
        relative_path = self._repository.normalize_match_path(file_path)
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
        if anchor_source_hash is not None:
            req["anchor_source_hash"] = anchor_source_hash
        graph = review_graph or self._review_graph_factory(None, None)
        checkpoint_key = (
            graph.checkpoint_key(req) if checkpoint_session is not None else None
        )
        if (
            load_checkpoint
            and checkpoint_key is not None
            and checkpoint_session is not None
        ):
            cached = checkpoint_session.get(f"file:{checkpoint_key}")
            if cached is not None and isinstance(cached.get("reviews"), list):
                try:
                    group = ReviewGroup.model_validate(cached)
                except ValidationError:
                    pass
                else:
                    if graph.checkpoint_evidence_valid(cached):
                        return _review_group_payload(
                            group,
                            relative_path=relative_path,
                            file_path=file_path,
                        )
        if cache_only:
            return None

        if source_view is None:
            result = graph.review(
                req,
                collect_navigation_evidence=checkpoint_key is not None,
                **({"emit": emit} if emit is not None else {}),
            )
        else:
            result = graph.review(
                req,
                collect_navigation_evidence=checkpoint_key is not None,
                **({"emit": emit} if emit is not None else {}),
                source_map=SourceMap(
                    relative_path,
                    snippet,
                    source=source_view.canonical,
                    anchor_source=source_view.raw,
                ),
            )
        navigation_evidence = result.get("navigation_evidence") if result else None
        if result:
            group = ReviewGroup.model_validate(result)
            result = _review_group_payload(
                group,
                relative_path=relative_path,
                file_path=file_path,
            )
            if emit is not None and group.reviews:
                emit(result)
                result = None
        if (
            checkpoint_key is not None
            and checkpoint_session is not None
            and result
            and (navigation_evidence is None or None not in navigation_evidence)
        ):
            checkpoint_session.put(
                f"file:{checkpoint_key}",
                {
                    "reviews": [
                        review.model_dump(mode="json") for review in group.reviews
                    ],
                    "navigation_evidence": navigation_evidence,
                },
            )
        return result if emit is None else None

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

    def review_patch(
        self,
        patch_file,
        *,
        model: str | None = None,
        memory_service: MemoryService | None = None,
        review_graph: Any | None = None,
        checkpoint_session: ReviewCheckpointSession | None = None,
        failures: list[ReviewFileFailure] | None = None,
        emit=None,
        on_summary=None,
        summary_input=None,
        begin_patch_entry=None,
    ):
        patch_text = Path(patch_file).read_text(encoding="utf-8")
        diff = unidiff.PatchSet.from_string(patch_text)
        if patch_text.strip() and not diff:
            raise ValueError("Patch file contains no file changes")
        logger.info("Parsed the patch file successfully.")
        file_reviews = []
        overall_summaries = []
        metisignore_spec = self._repository.load_metisignore()
        graph = review_graph or self._review_graph_factory(None, model)
        for entry_index, file_diff in enumerate(diff):
            if file_diff.is_removed_file or file_diff.is_binary_file:
                continue
            patch_path = file_diff.path
            if patch_path.startswith('"') and patch_path.endswith('"'):
                patch_path = os.fsdecode(
                    escape_decode(os.fsencode(patch_path[1:-1]))[0]
                )
            plugin = self._repository.get_plugin_for_path(patch_path)
            if not plugin:
                continue
            if not file_diff.added and not file_diff.removed:
                continue
            snippet = str(file_diff)
            language_prompts = plugin.get_prompts()
            try:
                source_path = resolve_path_within_root(
                    self._config.codebase_path,
                    Path(self._config.codebase_path).absolute() / patch_path,
                    preserve_aliases=True,
                )
                abs_path = str(source_path)
                relative_path = self._repository.normalize_match_path(abs_path)
                if self._repository.is_metisignored(abs_path, spec=metisignore_spec):
                    continue
                original_content = (
                    source_path.read_text(encoding="utf-8")
                    if source_path.exists()
                    else ""
                )
            except CancelledError:
                raise
            except Exception as exc:
                if failures is None:
                    raise
                failures.append(ReviewFileFailure(patch_path, str(exc)))
                continue
            if begin_patch_entry is not None:
                begin_patch_entry(entry_index, abs_path)
            threat_model_context = get_threat_model_context(
                memory_service,
                path=relative_path,
            )
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
                    if not isinstance(cached_review, dict) or not isinstance(
                        cached_review.get("reviews"), list
                    ):
                        raise ValueError("invalid patch checkpoint review")
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
                    if not graph.checkpoint_evidence_valid(cached):
                        raise ValueError("changed navigation evidence")
                    changes_summary = cached_summary
                except ValueError:
                    cached = None

            if cached is None:
                checkpoint_group: ReviewGroup | None = None
                try:
                    review_dict = graph.review(
                        req,
                        collect_navigation_evidence=checkpoint_key is not None,
                        **({"emit": emit} if emit is not None else {}),
                    )
                    navigation_evidence = (
                        review_dict.get("navigation_evidence") if review_dict else None
                    )
                    if review_dict:
                        checkpoint_group = ReviewGroup.model_validate(review_dict)
                        review_dict = _review_group_payload(
                            checkpoint_group,
                            relative_path=relative_path,
                            file_path=abs_path,
                        )
                except CancelledError:
                    raise
                except Exception as exc:
                    if failures is None:
                        raise
                    failures.append(ReviewFileFailure(patch_path, str(exc)))
                    if isinstance(exc, ModelProviderConfigurationError):
                        break
                    continue
                if review_dict:
                    issues = "\n".join(
                        summary_input(abs_path)
                        if summary_input is not None
                        else (
                            issue.get("issue", "")
                            for issue in review_dict.get("reviews", [])
                        )
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
                            patch_path,
                            issues,
                            summary_prompt,
                            model=model or self._config.llama_query_model,
                            chat_model_kwargs=self._config.chat_model_kwargs,
                            callbacks=self._config.usage_runtime.hooks.callbacks,
                        )
                if (
                    checkpoint_key is not None
                    and checkpoint_session is not None
                    and checkpoint_group is not None
                    and (navigation_evidence is None or None not in navigation_evidence)
                ):
                    checkpoint_session.put(
                        f"patch-file:{checkpoint_key}",
                        {
                            "review": {
                                "reviews": [
                                    review.model_dump(mode="json")
                                    for review in checkpoint_group.reviews
                                ]
                            },
                            "summary": changes_summary,
                            "navigation_evidence": navigation_evidence,
                        },
                    )

            if review_dict:
                if emit is None:
                    file_reviews.append(review_dict)
                elif not review_dict["reviews"]:
                    emit(review_dict)
            if changes_summary:
                if emit is None or on_summary is None:
                    overall_summaries.append(changes_summary)
                if on_summary is not None:
                    on_summary(changes_summary)
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
        "reviews": [
            normalize_review_fields(review.model_dump(mode="python"))
            for review in group.reviews
        ],
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
