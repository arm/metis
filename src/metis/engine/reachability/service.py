# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import json
import logging
import os

from metis.engine.llm_runner import JsonPromptRequest, JsonPromptRunner
from metis.utils import parse_json_output
from metis.reachability_settings import (
    DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
    DEFAULT_REACHABILITY_MAX_PATHS,
    DEFAULT_REACHABILITY_MAX_PATHS_PER_SINK,
    DEFAULT_REACHABILITY_WORKERS,
)

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
from .file_focus import FileFocusBuilder
from .domain import VulnerabilityFinding
from .options import ReachabilityReviewOptions
from .review_output import group_findings_as_reviews, reviews_for_findings
from .supplementary import SupplementaryAnalyzer

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

    def review_file(
        self,
        file_path,
        *,
        confirmation_model=None,
        max_workers=DEFAULT_REACHABILITY_WORKERS,
        max_paths=DEFAULT_REACHABILITY_MAX_PATHS,
        max_paths_per_sink=DEFAULT_REACHABILITY_MAX_PATHS_PER_SINK,
        max_path_length=DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
        progress_callback=None,
        reasoning_effort=None,
        source_functions=None,
        security_functions=None,
        domain_hints=None,
        domain_profiles=None,
        **_kwargs,
    ):
        options = ReachabilityReviewOptions(
            confirmation_model=confirmation_model,
            max_workers=max_workers,
            max_paths=max_paths,
            max_paths_per_sink=max_paths_per_sink,
            max_path_length=max_path_length,
            progress_callback=progress_callback,
            reasoning_effort=reasoning_effort,
            source_functions=source_functions,
            security_functions=security_functions,
            domain_hints=domain_hints,
            domain_profiles=domain_profiles,
        )
        abs_target, relative_target = self._normalize_target_file(file_path)
        graph = self._graphs.ensure_graph(
            progress_callback=options.progress_callback,
            source_functions=options.source_functions,
            security_functions=options.security_functions,
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
            "treesitter_file_paths_done",
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
            self._confirmer(model, options.reasoning_effort).confirm_paths_for_file(
                relative_target,
                source_to_file_paths,
                graph,
                max_workers=options.max_workers,
            )
            if source_to_file_paths
            else []
        )

        _emit_progress(
            options.progress_callback,
            "treesitter_file_review_done",
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
        confirmation_model=None,
        max_workers=DEFAULT_REACHABILITY_WORKERS,
        max_paths=DEFAULT_REACHABILITY_MAX_PATHS,
        max_paths_per_sink=DEFAULT_REACHABILITY_MAX_PATHS_PER_SINK,
        max_path_length=DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
        progress_callback=None,
        reasoning_effort=None,
        source_functions=None,
        security_functions=None,
        domain_hints=None,
        domain_profiles=None,
        confirm_paths=True,
        lens_profile="all",
        **_kwargs,
    ):
        options = ReachabilityReviewOptions(
            confirmation_model=confirmation_model,
            max_workers=max_workers,
            max_paths=max_paths,
            max_paths_per_sink=max_paths_per_sink,
            max_path_length=max_path_length,
            progress_callback=progress_callback,
            reasoning_effort=reasoning_effort,
            source_functions=source_functions,
            security_functions=security_functions,
            domain_hints=domain_hints,
            domain_profiles=domain_profiles,
            confirm_paths=confirm_paths,
            lens_profile=lens_profile,
        )
        graph, paths = self._graphs.get_codebase_graph_and_paths(
            max_path_length=options.max_path_length,
            progress_callback=options.progress_callback,
            source_functions=options.source_functions,
            security_functions=options.security_functions,
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
            "treesitter_paths_done",
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
            self._confirmer(model, options.reasoning_effort).confirm_paths(
                selected_paths,
                graph,
                max_workers=options.max_workers,
                progress_callback=options.progress_callback,
            )
            if selected_paths
            else []
        )

        deduped_findings, total_before, removed = self._finalize_findings(
            list(supplementary) + list(path_findings),
            graph,
            options,
            model=model,
        )

        reviews = group_findings_as_reviews(
            deduped_findings,
            graph,
            codebase_path=self._config.codebase_path,
        )
        _emit_progress(
            options.progress_callback,
            "treesitter_code_review_done",
            supplementary_findings=len(supplementary),
            path_findings=len(path_findings),
            raw_findings=total_before,
            deduped_findings=len(deduped_findings),
            removed_findings=removed,
            files=len(reviews),
        )
        return reviews

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
                max_tokens=6000,
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
        cached = self._supplementary_cache.get(key)
        if cached is not None:
            return list(cached)
        findings = SupplementaryAnalyzer(
            self._llm_provider,
            model,
            self._usage_runtime,
            self._config.codebase_path,
            reasoning_effort=options.reasoning_effort,
            domain_hints=options.domain_hints,
            domain_profiles=options.domain_profiles,
        ).analyze(
            graph,
            max_workers=options.max_workers,
            progress_callback=options.progress_callback,
            lens_profile=options.lens_profile,
        )
        self._supplementary_cache[key] = list(findings)
        return list(findings)

    def _finalize_findings(
        self,
        findings,
        graph,
        options: ReachabilityReviewOptions,
        *,
        model,
        target_file=None,
    ):
        return self._finalizer.finalize(
            findings,
            graph,
            max_path_length=options.max_path_length,
            max_paths_per_sink=options.max_paths_per_sink,
            target_file=target_file,
            final_adjudicator=lambda candidates: self.adjudicate_final_findings(
                candidates,
                model=model,
                reasoning_effort=options.reasoning_effort,
            ),
        )

    def _review_model(self, options: ReachabilityReviewOptions):
        return options.confirmation_model or self._config.llama_query_model

    def _confirmer(self, model, reasoning_effort=None):
        return VulnerabilityConfirmer(
            self._llm_provider,
            model,
            self._usage_runtime,
            self._config.codebase_path,
            reasoning_effort=reasoning_effort,
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
