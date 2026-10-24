# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import logging
from collections.abc import Callable
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from metis.engine.capabilities.manifest import CapabilityManifest
from metis.engine.capabilities.navigation import NavigationCapability
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.execution.contracts import NodeJobs
from metis.engine.threat_context_retrieval import get_threat_model_context
from metis.engine.threat_context_retrieval import threat_model_scope_policy
from metis.utils import resolve_path_within_root

from .domain import ReachabilityAnalysis
from .domain import VulnerabilityFinding
from .file_focus import FileFocusBuilder
from .finding_preparer import participates_in_file
from .finding_preparer import prepare_findings
from .graph_utils import _copy_graph_nodes
from .incremental_review import FrontierReviewOutcome
from .incremental_review import IncrementalGraphReviewer
from .options import ReachabilityReviewOptions
from .progress import ReachabilityProgress as Progress
from .progress import emit_phase_progress
from .progress import emit_progress

logger = logging.getLogger(__name__)


class ReachabilityService:
    def __init__(
        self,
        config,
        repository,
        llm_provider,
        usage_runtime,
        *,
        navigation_manifest: CapabilityManifest | None = None,
    ):
        self._config = config
        self._frontier_reviewer = IncrementalGraphReviewer(
            config,
            repository,
            llm_provider,
            usage_runtime,
            navigation_manifest=navigation_manifest,
        )

    def analyze_file(
        self,
        file_path,
        *,
        jobs: NodeJobs,
        options: ReachabilityReviewOptions,
        codegraph: CodeGraph,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
        memory_service=None,
        navigation: NavigationCapability | None = None,
    ):
        abs_target, relative_target = self._normalize_target_file(file_path)
        if codegraph.node_count() == 0:
            if diagnostic_callback is not None:
                diagnostic_callback(
                    CodeGraphDiagnostic(
                        relative_target,
                        "Reachability could not review the target because the "
                        "canonical CodeGraph is empty.",
                        severity="warning",
                        code="codegraph.empty",
                    )
                )
            return ReachabilityAnalysis(
                findings=(),
                target_file=relative_target,
                target_path=abs_target,
                codegraph_failures=(f"codegraph.empty:{relative_target}",),
            )
        focus = FileFocusBuilder(
            codegraph,
            max_path_length=options.max_path_length,
        ).build(relative_target)
        if not focus.target_nodes:
            if diagnostic_callback is not None:
                diagnostic_callback(
                    CodeGraphDiagnostic(
                        relative_target,
                        "Reachability could not review the target because it has no "
                        "function node in the canonical CodeGraph.",
                        severity="warning",
                        code="codegraph.target_missing",
                    )
                )
            return ReachabilityAnalysis(
                findings=(),
                target_file=relative_target,
                target_path=abs_target,
                codegraph_failures=(f"codegraph.target_missing:{relative_target}",),
            )
        analysis_graph = _copy_graph_nodes(codegraph, focus.node_names)
        outcome, prepared, raw_count = self._review_findings(
            analysis_graph,
            codegraph=codegraph,
            jobs=jobs,
            options=options,
            memory_service=memory_service,
            navigation=navigation,
            selected_node_ids=set(focus.target_nodes),
            selected_files={relative_target},
            target_file=relative_target,
        )
        emit_progress(
            options.progress_callback,
            Progress.FILE_REVIEW_DONE,
            file=relative_target,
            raw_findings=raw_count,
            findings=len(prepared),
            failed_nodes=len(outcome.failed_node_ids),
            planned_nodes=outcome.stats.planned_node_count,
            reviewed_nodes=outcome.stats.reviewed_node_count,
        )
        return ReachabilityAnalysis(
            findings=tuple(prepared),
            target_file=relative_target,
            target_path=abs_target,
            review_failures=outcome.failures,
        )

    def analyze_codebase(
        self,
        *,
        jobs: NodeJobs,
        options: ReachabilityReviewOptions,
        codegraph: CodeGraph,
        files=None,
        memory_service=None,
        navigation: NavigationCapability | None = None,
    ):
        selected_files = None
        if files is not None:
            selected_files = {
                self._normalize_target_file(path)[1] for path in dict.fromkeys(files)
            }
        if codegraph.node_count() == 0:
            return ReachabilityAnalysis(
                findings=(),
                codegraph_failures=("codegraph.empty",),
            )
        analysis_graph = codegraph
        selected_node_ids: set[str] | None = None
        missing_selected_files: list[str] = []
        if selected_files is not None:
            selected_node_ids = set()
            focus_nodes: set[str] = set()
            focus_builder = FileFocusBuilder(
                codegraph,
                max_path_length=options.max_path_length,
            )
            ordered_files = sorted(selected_files)
            emit_phase_progress(
                options.progress_callback, "analysis", 0, len(ordered_files)
            )
            present_files: set[str] = set()
            for node in codegraph.nodes.values():
                if node.file_path in selected_files:
                    selected_node_ids.add(node.unique_name)
                    present_files.add(node.file_path)
            for completed, selected_file in enumerate(ordered_files, start=1):
                if selected_file not in present_files:
                    missing_selected_files.append(selected_file)
                if completed == len(ordered_files):
                    focus_nodes = focus_builder.node_names_for_targets(
                        selected_node_ids
                    )
                emit_phase_progress(
                    options.progress_callback,
                    "analysis",
                    completed,
                    len(ordered_files),
                )
            analysis_graph = _copy_graph_nodes(codegraph, focus_nodes)
        if analysis_graph.node_count() == 0:
            return ReachabilityAnalysis(
                findings=(),
                codegraph_failures=tuple(
                    f"codegraph.target_missing:{file_path}"
                    for file_path in missing_selected_files
                )
                or ("codegraph.scope_empty",),
            )
        outcome, prepared, _ = self._review_findings(
            analysis_graph,
            codegraph=codegraph,
            jobs=jobs,
            options=options,
            memory_service=memory_service,
            navigation=navigation,
            selected_node_ids=selected_node_ids,
            selected_files=selected_files,
        )

        emit_progress(
            options.progress_callback,
            Progress.CODE_REVIEW_DONE,
            findings=len(prepared),
            failed_nodes=len(outcome.failed_node_ids),
            planned_nodes=outcome.stats.planned_node_count,
            reviewed_nodes=outcome.stats.reviewed_node_count,
            files=len(
                {
                    finding.primary_file or finding.sink_file or finding.source_file
                    for finding in prepared
                    if finding.primary_file or finding.sink_file or finding.source_file
                }
            ),
        )
        return ReachabilityAnalysis(
            findings=tuple(prepared),
            codegraph_failures=tuple(
                f"codegraph.target_missing:{file_path}"
                for file_path in missing_selected_files
            ),
            review_failures=outcome.failures,
        )

    def _review_findings(
        self,
        analysis_graph: CodeGraph,
        *,
        codegraph: CodeGraph,
        jobs: NodeJobs,
        options: ReachabilityReviewOptions,
        memory_service,
        navigation: NavigationCapability | None,
        selected_node_ids: set[str] | None,
        selected_files: set[str] | None,
        target_file: str | None = None,
    ) -> tuple[FrontierReviewOutcome, list[VulnerabilityFinding], int]:
        outcome = self._frontier_reviewer.review(
            analysis_graph,
            jobs=jobs,
            options=options,
            memory_service=memory_service,
            evidence_graph=codegraph,
            navigation=navigation,
            selected_node_ids=selected_node_ids,
        )
        findings = self._filter_authoritative_scope(outcome.findings, memory_service)
        if selected_files is not None:
            findings = [
                finding
                for finding in findings
                if any(
                    participates_in_file(finding, selected_file, analysis_graph)
                    for selected_file in selected_files
                )
            ]
        prepared = prepare_findings(
            findings,
            analysis_graph,
            max_path_length=options.max_path_length,
            target_file=target_file,
        )
        return outcome, prepared, len(findings)

    def _filter_authoritative_scope(
        self,
        findings: Sequence[VulnerabilityFinding],
        memory_service,
    ) -> list[VulnerabilityFinding]:
        context_by_file: dict[str, list[dict[str, Any]]] = {}
        kept: list[VulnerabilityFinding] = []
        for finding in findings:
            file_path = finding.primary_file or finding.sink_file or finding.source_file
            if file_path not in context_by_file:
                context_by_file[file_path] = get_threat_model_context(
                    memory_service,
                    path=file_path,
                )
            policy = threat_model_scope_policy(
                context_by_file[file_path],
                path=file_path,
            )
            if policy is None:
                kept.append(finding)
                continue
            logger.info(
                "Dropped %s:%s under authoritative threat-model scope from %s",
                file_path,
                finding.primary_line,
                policy.get("source_path"),
            )
        return kept

    def _normalize_target_file(self, file_path):
        root = Path(self._config.codebase_path).expanduser().resolve()
        resolved = resolve_path_within_root(root, file_path)
        return str(resolved), resolved.relative_to(root).as_posix()
