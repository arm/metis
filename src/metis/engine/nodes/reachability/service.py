# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import logging
import os
from collections.abc import Callable
from collections.abc import Sequence
from typing import Any

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.concurrency import serialized_progress_callback
from metis.engine.nodes.codegraph import CodeGraphService
from metis.engine.threat_context_retrieval import get_threat_model_context
from metis.engine.threat_context_retrieval import threat_model_scope_policy

from .domain import ReachabilityAnalysis
from .domain import VulnerabilityFinding
from .file_focus import FileFocusBuilder
from .finding_preparer import participates_in_file
from .finding_preparer import prepare_findings
from .graph_utils import _copy_graph_nodes
from .incremental_review import IncrementalGraphReviewer
from .options import ReachabilityReviewOptions
from .progress import ReachabilityProgress as Progress
from .progress import emit_progress

logger = logging.getLogger(__name__)


class ReachabilityService:
    def __init__(
        self,
        config,
        repository,
        llm_provider,
        usage_runtime,
        codegraphs: CodeGraphService,
    ):
        self._config = config
        self._frontier_reviewer = IncrementalGraphReviewer(
            config,
            repository,
            llm_provider,
            usage_runtime,
        )
        self._codegraphs = codegraphs

    def analyze_file(
        self,
        file_path,
        *,
        options: ReachabilityReviewOptions,
        codegraph: CodeGraph | None = None,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
        memory_service=None,
    ):
        options = self._review_options(options)
        abs_target, relative_target = self._normalize_target_file(file_path)
        graph = codegraph or self._load_graph(
            options=options,
            diagnostic_callback=diagnostic_callback,
        )
        if graph.node_count() == 0:
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
            graph,
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
        analysis_graph = _copy_graph_nodes(graph, focus.node_names)
        outcome = self._frontier_reviewer.review(
            analysis_graph,
            options=options,
            memory_service=memory_service,
            evidence_graph=graph,
        )
        scoped_findings = self._filter_authoritative_scope(
            outcome.findings,
            memory_service,
        )
        all_findings = [
            finding
            for finding in scoped_findings
            if participates_in_file(finding, relative_target, analysis_graph)
        ]
        prepared = prepare_findings(
            all_findings,
            analysis_graph,
            max_path_length=options.max_path_length,
            target_file=relative_target,
        )
        emit_progress(
            options.progress_callback,
            Progress.FILE_REVIEW_DONE,
            file=relative_target,
            raw_findings=len(all_findings),
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
        options: ReachabilityReviewOptions,
        files=None,
        codegraph: CodeGraph | None = None,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
        memory_service=None,
    ):
        options = self._review_options(options)
        graph = codegraph or self._load_graph(
            options=options,
            diagnostic_callback=diagnostic_callback,
        )
        selected_files = None
        if files is not None:
            selected_files = {
                self._normalize_target_file(path)[1] for path in dict.fromkeys(files)
            }
        if graph.node_count() == 0:
            return ReachabilityAnalysis(
                findings=(),
                codegraph_failures=("codegraph.empty",),
            )
        analysis_graph = graph
        missing_selected_files: list[str] = []
        if selected_files is not None:
            focus_nodes: set[str] = set()
            focus_builder = FileFocusBuilder(
                graph,
                max_path_length=options.max_path_length,
            )
            for selected_file in sorted(selected_files):
                focus = focus_builder.build(selected_file)
                focus_nodes.update(focus.node_names)
                if not focus.target_nodes:
                    missing_selected_files.append(selected_file)
            analysis_graph = _copy_graph_nodes(graph, focus_nodes)
        if analysis_graph.node_count() == 0:
            return ReachabilityAnalysis(
                findings=(),
                codegraph_failures=tuple(
                    f"codegraph.target_missing:{file_path}"
                    for file_path in missing_selected_files
                )
                or ("codegraph.scope_empty",),
            )
        outcome = self._frontier_reviewer.review(
            analysis_graph,
            options=options,
            memory_service=memory_service,
            evidence_graph=graph,
        )
        findings = self._filter_authoritative_scope(
            outcome.findings,
            memory_service,
        )
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

    def supports_file(self, file_path) -> bool:
        _abs_target, relative_target = self._normalize_target_file(file_path)
        return self._codegraphs.supports_file(
            relative_target
        ) and self._codegraphs.supports_semantics(relative_target)

    def analysis_graph(
        self,
        *,
        options: ReachabilityReviewOptions,
        codegraph: CodeGraph | None = None,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
    ) -> CodeGraph:
        options = self._review_options(options)
        return codegraph or self._load_graph(
            options=options,
            diagnostic_callback=diagnostic_callback,
        )

    def _load_graph(
        self,
        *,
        options: ReachabilityReviewOptions,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
    ) -> CodeGraph:
        reference = self._codegraphs.materialize(
            progress_callback=options.progress_callback,
            diagnostic_callback=diagnostic_callback,
        )
        return self._codegraphs.load(reference)

    def _review_options(self, options):
        if options.progress_callback is None:
            return options
        return options.with_progress_callback(
            serialized_progress_callback(options.progress_callback)
        )

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
        base_path = os.path.abspath(self._config.codebase_path)
        full = (
            file_path
            if os.path.isabs(str(file_path))
            else os.path.join(base_path, str(file_path))
        )
        abs_target = os.path.abspath(full)
        rel_target = os.path.relpath(abs_target, base_path).replace("\\", "/")
        return abs_target, rel_target
