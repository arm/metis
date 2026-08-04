# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
from typing import cast
from typing import TYPE_CHECKING

from metis.engine.execution.contracts import CapabilityRequirement
from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import CodeGraphReference
from metis.engine.nodes.reachability.options import ReachabilityReviewOptions
from metis.engine.runtime import EngineConfig
from metis.engine.repository import EngineRepository
from metis.engine.stages.review.models import ReviewCommand
from metis.engine.stages.review.models import ReviewDiagnostic
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import ReviewStatus
from metis.engine.stages.review.execution import combine_review_runs
from metis.engine.stages.review.execution import review_node_result
from metis.engine.stages.review.models import StandardReviewResult
from metis.engine.stages.review.scope import select_review_targets
from metis.utils import resolve_path_within_root

from .aggregation import ReviewResultAggregator
from .review_output import group_findings_as_reviews
from .review_output import reviews_for_findings

if TYPE_CHECKING:
    from metis.engine.capabilities.index import IndexCapability
    from metis.engine.nodes.simple_llm_review.service import SimpleLlmReviewService
    from metis.memory import MemoryService


logger = logging.getLogger(__name__)


def create_node(review_service: "ReachabilityReviewService") -> NodeRegistration:
    def execute(invocation: NodeInvocation) -> NodeResult:
        reference = cast(CodeGraphReference, invocation.inputs["codegraph"])
        review = review_service.run_review(
            cast(ReviewCommand, invocation.inputs["request"]),
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
            progress_callback=invocation.context.callbacks.progress,
        )
        return review_node_result(review)

    return NodeRegistration(
        name="reachability",
        stage="review",
        configuration=EmptyNodeConfiguration,
        inputs={"request": ReviewCommand, "codegraph": CodeGraphReference},
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
        codegraph,
        codegraph_diagnostics=(),
        codegraph_failed_files=(),
        memory_service: MemoryService | None = None,
        index: IndexCapability | None = None,
        progress_callback=None,
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
        in_codebase: list[str] = []
        outside_codebase: list[str] = []
        for path in files:
            try:
                resolved = resolve_path_within_root(self._config.codebase_path, path)
            except (OSError, ValueError):
                outside_codebase.append(path)
                continue
            in_codebase.append(str(resolved))
        supported = tuple(
            path
            for path in in_codebase
            if self._repository.normalize_match_path(path) not in unavailable
            and self.supports_file(path)
        )
        fallback = tuple(path for path in in_codebase if path not in supported)
        diagnostics = [
            ReviewDiagnostic(
                "review.codegraph_provider_warning",
                f"{item.file_path}: {item.message}",
                item.severity,
            )
            for item in codegraph_diagnostics
            if self._repository.normalize_match_path(item.file_path)
            in {self._repository.normalize_match_path(path) for path in files}
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
                    codegraph=codegraph,
                    memory_service=memory_service,
                    progress_callback=progress_callback,
                    diagnostics=diagnostics,
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
                    memory_service=memory_service,
                    index=index,
                    progress_callback=progress_callback,
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
        codegraph,
        memory_service: MemoryService | None,
        progress_callback,
        diagnostics: list[ReviewDiagnostic],
    ) -> ReviewRun:
        provider_diagnostics: list[CodeGraphDiagnostic] = []
        try:
            if command.mode == "file":
                reviewed = self.file_review(
                    files[0],
                    settings=self._settings,
                    progress_callback=progress_callback,
                    diagnostic_callback=provider_diagnostics.append,
                    codegraph=codegraph,
                )
                raw = {"reviews": [] if reviewed is None else [reviewed]}
            else:
                raw = {
                    "reviews": self.codebase_reviews(
                        files=files,
                        settings=self._settings,
                        progress_callback=progress_callback,
                        diagnostic_callback=provider_diagnostics.append,
                        codegraph=codegraph,
                    )
                }
            result = StandardReviewResult.model_validate(
                self.aggregate_results(
                    raw,
                    settings=self._settings,
                    memory_service=memory_service,
                    deduplicate=command.mode == "file",
                )
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
        codebase=False,
    ):
        settings = dict(settings or {})
        if codebase:
            settings.setdefault("lens_profile", "review")
        if progress_callback is not None:
            settings["progress_callback"] = progress_callback
        return ReachabilityReviewOptions.from_kwargs(
            settings,
            default_workers=self._config.max_workers,
        )

    def codebase_reviews(
        self,
        *,
        files=None,
        settings=None,
        progress_callback=None,
        diagnostic_callback=None,
        codegraph=None,
    ):
        options = self.review_options(
            settings=settings,
            progress_callback=progress_callback,
            codebase=True,
        )
        analysis = self._service.analyze_codebase(
            options=options,
            files=files,
            codegraph=codegraph,
            diagnostic_callback=diagnostic_callback,
        )
        return group_findings_as_reviews(
            analysis.findings,
            analysis.graph,
            codebase_path=self._config.codebase_path,
        )

    def file_review(
        self,
        file_path,
        *,
        settings=None,
        progress_callback=None,
        diagnostic_callback=None,
        codegraph=None,
    ):
        options = self.review_options(
            settings=settings,
            progress_callback=progress_callback,
        )
        analysis = self._service.analyze_file(
            file_path,
            options=options,
            codegraph=codegraph,
            diagnostic_callback=diagnostic_callback,
        )
        if analysis is None:
            return None
        return {
            "file": analysis.target_file,
            "file_path": analysis.target_path,
            "reviews": reviews_for_findings(
                analysis.findings,
                analysis.graph,
                codebase_path=self._config.codebase_path,
                target_file=analysis.target_file or "",
            ),
        }

    def aggregate_results(
        self,
        results: object,
        *,
        settings: dict[str, object] | None = None,
        memory_service: MemoryService | None = None,
        deduplicate: bool = True,
    ) -> object:
        return ReviewResultAggregator(
            self._config,
            settings or {},
            final_adjudicator=self._service.adjudicate_final_findings,
            memory_service=memory_service,
        ).aggregate(results, deduplicate=deduplicate)
