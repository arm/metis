# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import json
import logging
import os
import threading
from dataclasses import replace

from metis.engine.llm_runner import JsonPromptRequest, JsonPromptRunner
from metis.utils import parse_json_output
from .confirmer import VulnerabilityConfirmer
from .dedup import FINAL_CONSOLIDATION_SYSTEM_PROMPT
from .finding_finalizer import FindingFinalizer, participates_in_file
from .graph_cache import ReachabilityGraphCache
from .graph_utils import (
    _copy_graph_nodes,
    _emit_progress,
    graph_fingerprint,
    select_confirmation_paths,
)
from .limits import FINAL_ADJUDICATION_MAX_TOKENS
from .file_focus import FileFocusBuilder
from .domain import VulnerabilityFinding
from .options import ReachabilityReviewOptions
from .progress import ReachabilityProgress as Progress
from .review_output import group_findings_as_reviews, reviews_for_findings
from .supplementary import SupplementaryAnalyzer
from .triage import (
    ReachabilityTriageRequest,
    ReachabilityTriageRunner,
)
from .workers import serialized_progress_callback

logger = logging.getLogger(__name__)


def _parse_final_adjudication_response(raw):
    parsed = parse_json_output(raw)
    if isinstance(parsed, dict) and isinstance(parsed.get("groups"), list):
        return parsed
    return None


class TreeSitterReachabilityService:
    def __init__(self, config, repository, llm_provider, usage_runtime):
        self._config = config
        self._llm_provider = llm_provider
        self._usage_runtime = usage_runtime
        self._runner = JsonPromptRunner(llm_provider, usage_runtime)
        self._graphs = ReachabilityGraphCache(config, repository)
        self._finalizer = FindingFinalizer(config.codebase_path)
        self._supplementary_cache: dict[
            tuple[str | int, ...], list[VulnerabilityFinding]
        ] = {}
        self._supplementary_condition = threading.Condition()
        self._supplementary_inflight: set[tuple[str | int, ...]] = set()

    def review_file(
        self,
        file_path,
        *,
        options: ReachabilityReviewOptions,
    ):
        options = self._review_options(options)
        abs_target, relative_target = self._normalize_target_file(file_path)
        graph = self._graphs.ensure_graph(options=options)
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
            Progress.TREESITTER_FILE_PATHS_DONE,
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
            if source_to_file_paths
            else []
        )

        _emit_progress(
            options.progress_callback,
            Progress.TREESITTER_FILE_REVIEW_DONE,
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
        if not deduped:
            return {"file": relative_target, "file_path": abs_target, "reviews": []}

        reviews = reviews_for_findings(
            deduped,
            graph,
            codebase_path=self._config.codebase_path,
            target_file=relative_target,
        )
        return {"file": relative_target, "file_path": abs_target, "reviews": reviews}

    def review_codebase(
        self,
        *,
        options: ReachabilityReviewOptions,
        files=None,
    ):
        options = self._review_options(options)
        graph, paths = self._graphs.get_codebase_graph_and_paths(
            files=files,
            options=options,
        )
        if graph.node_count() == 0:
            return []
        selected_paths = []
        if options.confirm_paths:
            selected_paths = select_confirmation_paths(
                paths, graph, max_paths=options.max_paths
            )
        _emit_progress(
            options.progress_callback,
            Progress.TREESITTER_PATHS_DONE,
            paths=len(paths),
            selected=len(selected_paths),
            confirmation_enabled=bool(options.confirm_paths),
        )

        model = self._review_model(options)
        supplementary = self._supplementary_for_graph(
            graph,
            scope_id="whole_graph",
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

        deduped_findings, total_before, removed = self._finalize_findings(
            list(supplementary) + list(path_findings),
            graph,
            options,
            model=model,
            progress_counts={
                "supplementary_findings": len(supplementary),
                "path_findings": len(path_findings),
            },
        )

        reviews = group_findings_as_reviews(
            deduped_findings,
            graph,
            codebase_path=self._config.codebase_path,
        )
        _emit_progress(
            options.progress_callback,
            Progress.TREESITTER_CODE_REVIEW_DONE,
            supplementary_findings=len(supplementary),
            path_findings=len(path_findings),
            raw_findings=total_before,
            deduped_findings=len(deduped_findings),
            removed_findings=removed,
            files=len(reviews),
        )
        return reviews

    def supports_file(self, file_path) -> bool:
        try:
            _abs_target, relative_target = self._normalize_target_file(file_path)
        except Exception:
            return False
        return self._graphs.supports_file(relative_target)

    def triage_finding(
        self,
        finding: ReachabilityTriageRequest,
        *,
        options: ReachabilityReviewOptions,
        model_tools: tuple[object, ...] = (),
        model_tool_max_rounds: int | None = None,
        chat_model_kwargs: dict | None = None,
    ) -> dict:
        options = self._review_options(options)
        _abs_target, relative_target = self._normalize_target_file(finding.file_path)
        graph = self._graphs.ensure_graph(options=options)
        if graph.node_count() == 0:
            return {
                "status": "inconclusive",
                "reason": "No C/C++ reachability graph was available for triage.",
                "evidence": [],
                "resolution_chain": [],
                "unresolved_hops": ["reachability graph unavailable"],
                "evidence_obligations": ["reachability_context"],
                "evidence_coverage": {"reachability_context": 0},
                "missing_evidence": ["reachability_context"],
            }
        return ReachabilityTriageRunner(
            self._llm_provider,
            self._review_model(options),
            self._usage_runtime,
            self._config.codebase_path,
            options=options,
            chat_model_kwargs=chat_model_kwargs,
            model_tools=model_tools,
            max_tool_rounds=model_tool_max_rounds,
        ).triage(
            replace(finding, file_path=relative_target),
            graph,
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
            cached = self._supplementary_cache.get(key)
            if cached is not None:
                return list(cached)
            if key in self._supplementary_inflight:
                while key in self._supplementary_inflight:
                    self._supplementary_condition.wait()
                cached = self._supplementary_cache.get(key)
                if cached is not None:
                    return list(cached)
            self._supplementary_inflight.add(key)

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
