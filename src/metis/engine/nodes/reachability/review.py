# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from typing import cast

from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import CodeGraphReference
from metis.engine.execution.contracts import CapabilityRequirement
from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeJobs
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.nodes.reachability.options import ReachabilityReviewOptions
from metis.engine.repository import EngineRepository
from metis.engine.runtime import EngineConfig
from metis.engine.stages.review.checkpoints import ReviewCheckpointSession
from metis.engine.stages.review.execution import combine_review_runs
from metis.engine.stages.review.execution import review_node_result
from metis.engine.stages.review.models import ReviewCommand
from metis.engine.stages.review.models import ReviewDiagnostic
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import ReviewStatus
from metis.engine.stages.review.models import StandardReviewResult
from metis.engine.stages.review.scope import select_review_targets
from metis.utils import resolve_path_within_root

from .progress import emit_phase_progress
from .review_output import group_findings_as_reviews
from .review_output import reviews_for_findings

if TYPE_CHECKING:
    from metis.engine.capabilities.index import IndexCapability
    from metis.engine.nodes.reachability.domain import ReachabilityAnalysis
    from metis.engine.nodes.simple_llm_review.service import SimpleLlmReviewService
    from metis.memory import MemoryService


logger = logging.getLogger(__name__)
NODE_NAME = "reachability"


def create_node(review_service: ReachabilityReviewService) -> NodeRegistration:
    def execute(invocation: NodeInvocation) -> NodeResult:
        callbacks = invocation.context.callbacks
        checkpoint_session = (
            ReviewCheckpointSession(NODE_NAME, callbacks)
            if callbacks.checkpoint is not None or callbacks.resume is not None
            else None
        )
        reference = cast(CodeGraphReference, invocation.inputs["codegraph"])
        review = review_service.run_review(
            cast(ReviewCommand, invocation.inputs["request"]),
            jobs=invocation.context.jobs,
            model=invocation.context.runtime.model,
            codegraph=invocation.context.codegraphs.load(reference),
            codegraph_diagnostics=reference.diagnostics,
            codegraph_failed_files=reference.failed_files,
            memory_service=cast(
                "MemoryService | None",
                invocation.context.capabilities.get("memory"),
            ),
            index=cast(
                "IndexCapability | None",
                invocation.context.capabilities.get("index"),
            ),
            progress_callback=invocation.context.report_progress,
            checkpoint_session=checkpoint_session,
        )
        return review_node_result(review)

    return NodeRegistration(
        name=NODE_NAME,
        stage="review",
        configuration=EmptyNodeConfiguration,
        inputs={
            "request": ReviewCommand,
            "codegraph": CodeGraphReference,
        },
        outputs={"review": ReviewRun},
        execute=execute,
        capabilities={
            "index": CapabilityRequirement.OPTIONAL,
            "memory": CapabilityRequirement.OPTIONAL,
        },
    )


class ReachabilityReviewService:
    def __init__(
        self,
        config: EngineConfig,
        repository: EngineRepository,
        reachability_service,
        simple_llm_review: SimpleLlmReviewService | None,
        settings: dict[str, object] | None = None,
    ) -> None:
        self._config = config
        self._repository = repository
        self._service = reachability_service
        self._simple_llm_review = simple_llm_review
        self._settings = dict(settings or {})

    def run_review(
        self,
        command: ReviewCommand,
        *,
        jobs: NodeJobs,
        model: str | None = None,
        codegraph,
        codegraph_diagnostics=(),
        codegraph_failed_files=(),
        memory_service: MemoryService | None = None,
        index: IndexCapability | None = None,
        progress_callback=None,
        checkpoint_session: ReviewCheckpointSession | None = None,
    ) -> ReviewRun:
        if command.mode == "patch":
            return ReviewRun(
                ReviewStatus.INCONCLUSIVE,
                StandardReviewResult(reviews=[]),
                (
                    ReviewDiagnostic(
                        "review.reachability_patch_unsupported",
                        "Reachability review does not support patch input",
                        "warning",
                    ),
                ),
            )
        files = select_review_targets(self._repository, command)
        unavailable = {
            self._repository.normalize_match_path(path)
            for path in codegraph_failed_files
        }
        selected_match_paths = {
            self._repository.normalize_match_path(path) for path in files
        }
        supported_files: list[str] = []
        fallback_files: list[str] = []
        outside_codebase: list[str] = []
        emit_phase_progress(progress_callback, "scope", 0, len(files))
        for completed, path in enumerate(files, start=1):
            try:
                resolved = resolve_path_within_root(self._config.codebase_path, path)
            except (OSError, ValueError):
                outside_codebase.append(path)
            else:
                resolved_path = str(resolved)
                if self._repository.normalize_match_path(
                    resolved_path
                ) not in unavailable and self.supports_file(resolved_path):
                    supported_files.append(resolved_path)
                else:
                    fallback_files.append(resolved_path)
            emit_phase_progress(progress_callback, "scope", completed, len(files))
        supported = tuple(supported_files)
        fallback = tuple(fallback_files)
        diagnostics = [
            ReviewDiagnostic(
                "review.codegraph_provider_warning",
                f"{item.file_path}: {item.message}",
                item.severity,
            )
            for item in codegraph_diagnostics
            if self._repository.normalize_match_path(item.file_path)
            in selected_match_paths
        ]
        if outside_codebase:
            diagnostics.append(
                ReviewDiagnostic(
                    "review.target_outside_codebase",
                    "Review target is outside the codebase: "
                    + ", ".join(outside_codebase),
                    "warning",
                )
            )
        if fallback:
            logger.debug(
                "Reachability review is unavailable for %s; using simple LLM "
                "review fallback",
                ", ".join(fallback),
            )
        reviews: list[ReviewRun] = []
        if supported:
            reviews.append(
                self._run_reachability_review(
                    command,
                    supported,
                    model=model,
                    codegraph=codegraph,
                    jobs=jobs,
                    memory_service=memory_service,
                    progress_callback=progress_callback,
                    diagnostics=diagnostics,
                    checkpoint_session=checkpoint_session,
                )
            )
        elif diagnostics:
            reviews.append(
                ReviewRun(
                    ReviewStatus.INCONCLUSIVE,
                    StandardReviewResult(reviews=[]),
                    tuple(diagnostics),
                )
            )
        if fallback and self._simple_llm_review is not None:
            reviews.append(
                self._simple_llm_review.run_files(
                    fallback,
                    jobs=jobs,
                    memory_service=memory_service,
                    index=index,
                    progress_callback=progress_callback,
                    checkpoint_session=checkpoint_session,
                    model=model,
                )
            )
        if not reviews:
            return ReviewRun(
                ReviewStatus.SUCCEEDED if fallback else ReviewStatus.INCONCLUSIVE,
                StandardReviewResult(reviews=[]),
            )
        return combine_review_runs(tuple(reviews))

    def _run_reachability_review(
        self,
        command: ReviewCommand,
        files: tuple[str, ...],
        *,
        model: str | None,
        codegraph,
        jobs: NodeJobs,
        memory_service: MemoryService | None,
        progress_callback,
        diagnostics: list[ReviewDiagnostic],
        checkpoint_session: ReviewCheckpointSession | None,
    ) -> ReviewRun:
        provider_diagnostics: list[CodeGraphDiagnostic] = []
        settings = {
            **self._settings,
            "confirmation_model": model or self._config.llama_query_model,
        }
        try:
            if command.mode == "file":
                reviewed, analysis = self.file_review(
                    files[0],
                    settings=settings,
                    jobs=jobs,
                    progress_callback=progress_callback,
                    diagnostic_callback=provider_diagnostics.append,
                    codegraph=codegraph,
                    memory_service=memory_service,
                    checkpoint_session=checkpoint_session,
                )
                raw = {"reviews": [] if reviewed is None else [reviewed]}
            else:
                codebase_groups, analysis = self.codebase_reviews(
                    files=files,
                    settings=settings,
                    jobs=jobs,
                    progress_callback=progress_callback,
                    diagnostic_callback=provider_diagnostics.append,
                    codegraph=codegraph,
                    memory_service=memory_service,
                    checkpoint_session=checkpoint_session,
                )
                raw = {"reviews": codebase_groups}
            result = StandardReviewResult.model_validate(raw)
            codegraph_failures = (
                tuple(dict.fromkeys(analysis.codegraph_failures))
                if analysis is not None
                else ()
            )
            if codegraph_failures:
                failure_count = len(codegraph_failures)
                target_label = "target" if failure_count == 1 else "targets"
                diagnostics.append(
                    ReviewDiagnostic(
                        "review.frontier_analysis_partial",
                        "Reachability review could not fully analyze "
                        f"{failure_count} selected {target_label}.",
                        "warning",
                    )
                )
            review_failures = analysis.review_failures if analysis is not None else ()
            diagnostics.extend(
                ReviewDiagnostic(
                    f"review.frontier_failure.discovery.{failure.kind}",
                    f"Reachability discovery failure for {failure.function_id}.",
                    "warning",
                )
                for failure in review_failures
            )
        except RuntimeError as exc:
            diagnostics.append(ReviewDiagnostic("review.reachability_failed", str(exc)))
            return ReviewRun(ReviewStatus.FAILED, None, tuple(diagnostics))
        diagnostics.extend(
            ReviewDiagnostic(
                "review.reachability_provider_error"
                if item.severity == "error"
                else "review.reachability_provider_warning",
                f"{item.file_path}: {item.message}",
                item.severity,
            )
            for item in provider_diagnostics
        )
        status = ReviewStatus.INCONCLUSIVE if diagnostics else ReviewStatus.SUCCEEDED
        return ReviewRun(status, result, tuple(diagnostics))

    def supports_file(self, file_path):
        return self._service.supports_file(str(file_path))

    def review_options(
        self,
        *,
        settings=None,
        progress_callback=None,
        checkpoint_session: ReviewCheckpointSession | None = None,
    ):
        settings = dict(settings or {})
        if progress_callback is not None:
            settings["progress_callback"] = progress_callback
        if checkpoint_session is not None:
            settings["checkpoint_session"] = checkpoint_session
        return ReachabilityReviewOptions(**settings)

    def codebase_reviews(
        self,
        *,
        jobs: NodeJobs,
        files=None,
        settings=None,
        progress_callback=None,
        diagnostic_callback=None,
        codegraph=None,
        memory_service: MemoryService | None = None,
        checkpoint_session: ReviewCheckpointSession | None = None,
    ) -> tuple[list[dict[str, object]], ReachabilityAnalysis]:
        options = self.review_options(
            settings=settings,
            progress_callback=progress_callback,
            checkpoint_session=checkpoint_session,
        )
        analysis = self._service.analyze_codebase(
            jobs=jobs,
            options=options,
            files=files,
            codegraph=codegraph,
            diagnostic_callback=diagnostic_callback,
            memory_service=memory_service,
        )
        return (
            group_findings_as_reviews(
                analysis.findings,
                codebase_path=self._config.codebase_path,
            ),
            analysis,
        )

    def file_review(
        self,
        file_path,
        *,
        jobs: NodeJobs,
        settings=None,
        progress_callback=None,
        diagnostic_callback=None,
        codegraph=None,
        memory_service: MemoryService | None = None,
        checkpoint_session: ReviewCheckpointSession | None = None,
    ) -> tuple[dict[str, object] | None, ReachabilityAnalysis | None]:
        options = self.review_options(
            settings=settings,
            progress_callback=progress_callback,
            checkpoint_session=checkpoint_session,
        )
        analysis = self._service.analyze_file(
            file_path,
            jobs=jobs,
            options=options,
            codegraph=codegraph,
            diagnostic_callback=diagnostic_callback,
            memory_service=memory_service,
        )
        if analysis is None:
            return None, None
        return (
            {
                "file": analysis.target_file,
                "file_path": analysis.target_path,
                "reviews": reviews_for_findings(
                    analysis.findings,
                    codebase_path=self._config.codebase_path,
                ),
            },
            analysis,
        )
