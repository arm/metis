# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import json
import logging
import os
import threading
from collections.abc import Callable

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.nodes.codegraph import CodeGraphService
from metis.engine.llm_runner import JsonPromptRequest, JsonPromptRunner
from metis.utils import parse_json_output
from .confirmer import VulnerabilityConfirmer
from .dedup import FINAL_CONSOLIDATION_SYSTEM_PROMPT
from .finding_finalizer import FindingFinalizer, participates_in_file
from .context import ReachabilityContext
from .graph_utils import (
    _copy_graph_nodes,
    _emit_progress,
    graph_fingerprint,
    select_confirmation_paths,
)
from .limits import FINAL_ADJUDICATION_MAX_TOKENS
from .file_focus import FileFocusBuilder
from .domain import ReachabilityAnalysis
from .domain import VulnerabilityFinding
from .options import ReachabilityReviewOptions
from .progress import ReachabilityProgress as Progress
from .supplementary import SupplementaryAnalyzer
from .workers import serialized_progress_callback

logger = logging.getLogger(__name__)


def _parse_final_adjudication_response(raw):
    parsed = parse_json_output(raw)
    if isinstance(parsed, dict) and isinstance(parsed.get("groups"), list):
        return parsed
    return None


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
        self._llm_provider = llm_provider
        self._usage_runtime = usage_runtime
        self._runner = JsonPromptRunner(llm_provider, usage_runtime)
        self._context = ReachabilityContext(
            codegraphs,
        )
        self._finalizer = FindingFinalizer(config.codebase_path)
        self._supplementary_cache: dict[
            tuple[str | int, ...], list[VulnerabilityFinding]
        ] = {}
        self._supplementary_condition = threading.Condition()
        self._supplementary_inflight: set[tuple[str | int, ...]] = set()

    def analyze_file(
        self,
        file_path,
        *,
        options: ReachabilityReviewOptions,
        codegraph: CodeGraph | None = None,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
    ):
        options = self._review_options(options)
        abs_target, relative_target = self._normalize_target_file(file_path)
        graph = codegraph or self._context.graph(
            options=options,
            diagnostic_callback=diagnostic_callback,
        )
        if graph.node_count() == 0:
            return None

        focus = FileFocusBuilder(
            graph,
            max_path_length=options.max_path_length,
            max_incoming_paths=options.max_paths if options.max_paths > 0 else None,
        ).build(relative_target)
        source_to_file_paths = focus.incoming_paths
        outgoing_context_paths = focus.outgoing_context_paths
        _emit_progress(
            options.progress_callback,
            Progress.FILE_PATHS_DONE,
            file=relative_target,
            paths=len(source_to_file_paths),
            source_to_file_paths=len(source_to_file_paths),
            outgoing_context_paths=len(outgoing_context_paths),
            focus_nodes=len(focus.node_names),
        )

        model = self._review_model(options)
        focus_graph = _copy_graph_nodes(graph, focus.node_names)
        if focus_graph.node_count() == 0:
            return None
        supplementary = self._supplementary_for_graph(
            focus_graph,
            scope_id=relative_target,
            model=model,
            options=options,
        )

        path_findings = (
            self._confirmer(model, options).confirm_paths_for_file(
                relative_target,
                source_to_file_paths,
                graph,
                options,
            )
            if options.confirm_paths and source_to_file_paths
            else []
        )

        _emit_progress(
            options.progress_callback,
            Progress.FILE_REVIEW_DONE,
            file=relative_target,
            supplementary_findings=len(supplementary),
            path_findings=len(path_findings),
        )

        all_findings = [
            finding
            for finding in list(supplementary) + list(path_findings)
            if participates_in_file(finding, relative_target, graph)
        ]
        deduped, _total, _removed = self._finalize_findings(
            all_findings,
            graph,
            options,
            model=model,
            target_file=relative_target,
        )
        return ReachabilityAnalysis(
            graph=graph,
            findings=tuple(deduped),
            target_file=relative_target,
            target_path=abs_target,
        )

    def analyze_codebase(
        self,
        *,
        options: ReachabilityReviewOptions,
        files=None,
        codegraph: CodeGraph | None = None,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
    ):
        options = self._review_options(options)
        graph = codegraph or self._context.graph(
            options=options,
            diagnostic_callback=diagnostic_callback,
        )
        selected_files = None
        if files is not None:
            selected_files = {
                self._normalize_target_file(path)[1] for path in dict.fromkeys(files)
            }
        graph, paths = self._context.graph_and_paths(
            options=options,
            codegraph=graph,
            diagnostic_callback=diagnostic_callback,
        )
        if selected_files is not None:
            paths = [
                path
                for path in paths
                if any(
                    (node := graph.get_node(node_name)) is not None
                    and node.file_path in selected_files
                    for node_name in path.path
                )
            ]
        if graph.node_count() == 0:
            return ReachabilityAnalysis(graph=graph, findings=())
        selected_paths = []
        if options.confirm_paths:
            selected_paths = select_confirmation_paths(
                paths, graph, max_paths=options.max_paths
            )
        _emit_progress(
            options.progress_callback,
            Progress.PATHS_DONE,
            paths=len(paths),
            selected=len(selected_paths),
            confirmation_enabled=bool(options.confirm_paths),
        )

        model = self._review_model(options)
        supplementary_graph = graph
        supplementary_scope: object = "whole_graph"
        if selected_files is not None:
            focus_nodes = {
                node.unique_name
                for node in graph.nodes.values()
                if node.file_path in selected_files
            }
            for path in paths:
                focus_nodes.update(path.path)
            supplementary_graph = _copy_graph_nodes(graph, focus_nodes)
            supplementary_scope = tuple(sorted(selected_files))
        supplementary = self._supplementary_for_graph(
            supplementary_graph,
            scope_id=supplementary_scope,
            model=model,
            options=options,
        )
        path_findings = (
            self._confirmer(model, options).confirm_paths(
                selected_paths,
                graph,
                options,
            )
            if selected_paths
            else []
        )

        findings = list(supplementary) + list(path_findings)
        if selected_files is not None:
            findings = [
                finding
                for finding in findings
                if any(
                    participates_in_file(finding, selected_file, graph)
                    for selected_file in selected_files
                )
            ]
        deduped_findings, total_before, removed = self._finalize_findings(
            findings,
            graph,
            options,
            model=model,
            progress_counts={
                "supplementary_findings": len(supplementary),
                "path_findings": len(path_findings),
            },
        )

        _emit_progress(
            options.progress_callback,
            Progress.CODE_REVIEW_DONE,
            supplementary_findings=len(supplementary),
            path_findings=len(path_findings),
            raw_findings=total_before,
            deduped_findings=len(deduped_findings),
            removed_findings=removed,
            files=len(
                {
                    finding.primary_file or finding.sink_file or finding.source_file
                    for finding in deduped_findings
                    if finding.primary_file or finding.sink_file or finding.source_file
                }
            ),
        )
        return ReachabilityAnalysis(graph=graph, findings=tuple(deduped_findings))

    def supports_file(self, file_path) -> bool:
        try:
            _abs_target, relative_target = self._normalize_target_file(file_path)
        except Exception:
            return False
        return self._context.supports_file(relative_target)

    def analysis_graph(
        self,
        *,
        options: ReachabilityReviewOptions,
        codegraph: CodeGraph | None = None,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
    ) -> CodeGraph:
        options = self._review_options(options)
        return codegraph or self._context.graph(
            options=options,
            diagnostic_callback=diagnostic_callback,
        )

    def _review_options(self, options):
        if options.progress_callback is None:
            return options
        return options.with_progress_callback(
            serialized_progress_callback(options.progress_callback)
        )

    def adjudicate_final_findings(self, candidates, *, model, reasoning_effort=None):
        return self._adjudicate_final_findings(
            candidates,
            model=model,
            reasoning_effort=reasoning_effort,
        )

    def _adjudicate_final_findings(self, candidates, *, model, reasoning_effort=None):
        if not candidates:
            return None
        return self._runner.invoke(
            JsonPromptRequest(
                model=model,
                max_tokens=FINAL_ADJUDICATION_MAX_TOKENS,
                temperature=0.1,
                system_prompt=FINAL_CONSOLIDATION_SYSTEM_PROMPT,
                user_prompt="Candidate findings JSON:\n{candidate_findings}",
                variables={
                    "candidate_findings": json.dumps(candidates, separators=(",", ":"))
                },
                parse=_parse_final_adjudication_response,
                logger=logger,
                label="Final reachability dedup adjudication",
                batch_size=len(candidates),
                invalid_message="expected JSON object with groups list",
                final_keep_message="keeping this batch unchanged",
                reasoning_effort=reasoning_effort,
            )
        )

    def _supplementary_for_graph(
        self,
        graph,
        *,
        scope_id="whole_graph",
        model,
        options: ReachabilityReviewOptions,
    ):
        cache_options = options.with_confirmation_model(model)
        key = cache_options.supplementary_cache_key(
            scope_id,
            graph_fingerprint(graph),
        )
        with self._supplementary_condition:
            while True:
                cached = self._supplementary_cache.get(key)
                if cached is not None:
                    return list(cached)
                if key not in self._supplementary_inflight:
                    self._supplementary_inflight.add(key)
                    break
                self._supplementary_condition.wait()

        try:
            findings = SupplementaryAnalyzer(
                self._llm_provider,
                model,
                self._usage_runtime,
                self._config.codebase_path,
                options=options,
            ).analyze(
                graph,
                options=options,
            )
        except Exception:
            with self._supplementary_condition:
                self._supplementary_inflight.discard(key)
                self._supplementary_condition.notify_all()
            raise

        with self._supplementary_condition:
            self._supplementary_cache[key] = list(findings)
            self._supplementary_inflight.discard(key)
            self._supplementary_condition.notify_all()
        return list(findings)

    def _finalize_findings(
        self,
        findings,
        graph,
        options: ReachabilityReviewOptions,
        *,
        model,
        target_file=None,
        progress_counts=None,
    ):
        progress_counts = dict(progress_counts or {})
        _emit_progress(
            options.progress_callback,
            Progress.FINDINGS_FINALIZATION_START,
            candidates=len(findings),
            file=target_file,
            **progress_counts,
        )

        def _adjudication_progress(payload):
            _emit_progress(
                options.progress_callback,
                Progress.FINDINGS_FINALIZATION_PROGRESS,
                file=target_file,
                **payload,
                **progress_counts,
            )

        def _adjudicate_candidates(candidates):
            return self.adjudicate_final_findings(
                candidates,
                model=model,
                reasoning_effort=options.reasoning_effort,
            )

        finalized = self._finalizer.finalize(
            findings,
            graph,
            options=options,
            target_file=target_file,
            final_adjudicator=_adjudicate_candidates,
            final_adjudication_progress=_adjudication_progress,
        )
        deduped, total_before, removed = finalized
        _emit_progress(
            options.progress_callback,
            Progress.FINDINGS_FINALIZATION_DONE,
            candidates=len(findings),
            raw_findings=total_before,
            deduped_findings=len(deduped),
            removed_findings=removed,
            file=target_file,
            **progress_counts,
        )
        return finalized

    def _review_model(self, options: ReachabilityReviewOptions):
        return options.confirmation_model or self._config.llama_query_model

    def _confirmer(self, model, options):
        return VulnerabilityConfirmer(
            self._llm_provider,
            model,
            self._usage_runtime,
            self._config.codebase_path,
            options,
        )

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
