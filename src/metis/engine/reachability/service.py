# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Full-codebase tree-sitter reachability service."""

from __future__ import annotations

import copy
import os

from metis.reachability_settings import (
    DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
    DEFAULT_REACHABILITY_MAX_PATHS,
    DEFAULT_REACHABILITY_MAX_PATHS_PER_SINK,
    DEFAULT_REACHABILITY_WORKERS,
)

from .confirmer import VulnerabilityConfirmer
from .finding_finalizer import FindingFinalizer
from .graph_cache import ReachabilityGraphCache
from .graph_utils import (
    _copy_graph_nodes,
    graph_fingerprint,
    select_confirmation_paths,
)
from .models import VulnerabilityFinding
from .supplementary import SupplementaryAnalyzer
from .file_focus import FileFocusBuilder
from .review_output import group_findings_as_reviews, reviews_for_findings
from .scope import ReachabilityReviewScope, ReachabilityScopeResult


class TreeSitterReachabilityService:
    """Coordinate graph building, path tracing, supplementary lenses, and output."""

    def __init__(self, config, repository, llm_provider, usage_runtime):
        self._config = config
        self._llm_provider = llm_provider
        self._usage_runtime = usage_runtime
        self._graphs = ReachabilityGraphCache(config, repository)
        self._finalizer = FindingFinalizer(config.codebase_path)
        self._supplementary_cache: dict[
            tuple[str | int, ...], list[VulnerabilityFinding]
        ] = {}
        self._file_review_cache = {}

    def build_graph(self, files=None, *, progress_callback=None):
        return self._graphs.build_graph(files, progress_callback=progress_callback)

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
        abs_target, relative_target = self._normalize_target_file(file_path)
        graph = self._graphs.ensure_graph(
            progress_callback=progress_callback,
            source_functions=source_functions,
            security_functions=security_functions,
        )
        if graph.node_count() == 0:
            return None

        scope = self._file_scope(
            graph,
            abs_target=abs_target,
            relative_target=relative_target,
            max_paths=max_paths,
            max_path_length=max_path_length,
            progress_callback=progress_callback,
        )
        if scope is None:
            return None

        model = confirmation_model or self._config.llama_query_model
        cache_key = self._file_review_cache_key(
            scope,
            model=model,
            reasoning_effort=reasoning_effort,
            max_paths_per_sink=max_paths_per_sink,
            max_path_length=max_path_length,
            domain_hints=domain_hints,
            domain_profiles=domain_profiles,
        )
        cached = self._file_review_cache.get(cache_key)
        if cached is not None:
            result, stats = cached
            self._emit_file_done(progress_callback, relative_target, **stats)
            return copy.deepcopy(result)

        scope_result = self._analyze_scope(
            scope,
            model=model,
            max_workers=max_workers,
            max_paths_per_sink=max_paths_per_sink,
            max_path_length=max_path_length,
            progress_callback=progress_callback,
            reasoning_effort=reasoning_effort,
            domain_hints=domain_hints,
            domain_profiles=domain_profiles,
        )
        result = self._render_file_scope(scope, scope_result.findings)
        stats = {
            "supplementary_findings": scope_result.supplementary_count,
            "path_findings": scope_result.path_count,
        }
        self._file_review_cache[cache_key] = (copy.deepcopy(result), stats)
        self._emit_file_done(progress_callback, relative_target, **stats)
        return result

    @staticmethod
    def _emit_file_done(
        progress_callback, relative_target, *, supplementary_findings, path_findings
    ):
        if progress_callback:
            progress_callback(
                {
                    "event": "treesitter_file_review_done",
                    "file": relative_target,
                    "supplementary_findings": supplementary_findings,
                    "path_findings": path_findings,
                }
            )

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
        graph, paths = self.get_codebase_graph_and_paths(
            max_path_length=max_path_length,
            progress_callback=progress_callback,
            source_functions=source_functions,
            security_functions=security_functions,
        )
        if graph.node_count() == 0:
            return []
        selected_paths = []
        if confirm_paths:
            selected_paths = select_confirmation_paths(
                paths, graph, max_paths=max_paths
            )
        scope = ReachabilityReviewScope(
            scope_id="whole_graph",
            analysis_graph=graph,
            finalizer_graph=graph,
            paths_to_confirm=selected_paths,
            lens_profile=lens_profile,
        )
        if progress_callback:
            progress_callback(
                {
                    "event": "treesitter_paths_done",
                    "paths": len(paths),
                    "selected": len(selected_paths),
                    "confirmation_enabled": bool(confirm_paths),
                }
            )

        model = confirmation_model or self._config.llama_query_model
        scope_result = self._analyze_scope(
            scope,
            model=model,
            max_workers=max_workers,
            max_paths_per_sink=max_paths_per_sink,
            max_path_length=max_path_length,
            progress_callback=progress_callback,
            reasoning_effort=reasoning_effort,
            domain_hints=domain_hints,
            domain_profiles=domain_profiles,
        )
        reviews = group_findings_as_reviews(
            scope_result.findings,
            codebase_path=self._config.codebase_path,
        )
        if progress_callback:
            progress_callback(
                {
                    "event": "treesitter_code_review_done",
                    "supplementary_findings": scope_result.supplementary_count,
                    "path_findings": scope_result.path_count,
                    "raw_findings": scope_result.total_before,
                    "deduped_findings": len(scope_result.findings),
                    "removed_findings": scope_result.removed,
                    "files": len(reviews),
                }
            )
        return reviews

    def _file_scope(
        self,
        graph,
        *,
        abs_target,
        relative_target,
        max_paths,
        max_path_length,
        progress_callback=None,
    ):
        focus = FileFocusBuilder(
            graph,
            max_path_length=max_path_length,
            max_incoming_paths=max_paths if max_paths > 0 else None,
        ).build(relative_target)
        if progress_callback:
            progress_callback(
                {
                    "event": "treesitter_file_paths_done",
                    "file": relative_target,
                    "paths": len(focus.incoming_paths),
                    "source_to_file_paths": len(focus.incoming_paths),
                    "outgoing_context_paths": len(focus.outgoing_context_paths),
                    "focus_nodes": len(focus.node_names),
                }
            )
        focus_graph = _copy_graph_nodes(graph, focus.node_names)
        if focus_graph.node_count() == 0:
            return None
        return ReachabilityReviewScope(
            scope_id=relative_target,
            analysis_graph=focus_graph,
            finalizer_graph=graph,
            paths_to_confirm=focus.incoming_paths,
            target_file=relative_target,
            file_path=abs_target,
            strict_file=True,
        )

    def _analyze_scope(
        self,
        scope: ReachabilityReviewScope,
        *,
        model,
        max_workers,
        max_paths_per_sink,
        max_path_length,
        progress_callback=None,
        reasoning_effort=None,
        domain_hints=None,
        domain_profiles=None,
    ):
        supplementary = self._ensure_supplementary(
            scope.analysis_graph,
            scope_id=scope.scope_id,
            model=model,
            max_workers=max_workers,
            progress_callback=progress_callback,
            reasoning_effort=reasoning_effort,
            lens_profile=scope.lens_profile,
            domain_hints=domain_hints,
            domain_profiles=domain_profiles,
        )
        path_findings = self._confirm_scope_paths(
            scope,
            model=model,
            max_workers=max_workers,
            progress_callback=progress_callback,
            reasoning_effort=reasoning_effort,
        )
        findings = list(supplementary) + list(path_findings)
        if scope.target_file:
            findings = [
                finding
                for finding in findings
                if self._finalizer.participates_in_file(
                    finding, scope.target_file, scope.finalizer_graph
                )
            ]
        deduped, total_before, removed = self._finalizer.finalize(
            findings,
            scope.finalizer_graph,
            max_path_length=max_path_length,
            max_paths_per_sink=max_paths_per_sink,
            target_file=scope.target_file,
            strict_file=scope.strict_file,
        )
        return ReachabilityScopeResult(
            findings=deduped,
            total_before=total_before,
            removed=removed,
            supplementary_count=len(supplementary),
            path_count=len(path_findings),
        )

    def _confirm_scope_paths(
        self,
        scope: ReachabilityReviewScope,
        *,
        model,
        max_workers,
        progress_callback=None,
        reasoning_effort=None,
    ):
        if not scope.paths_to_confirm:
            return []
        confirmer = VulnerabilityConfirmer(
            self._llm_provider,
            model,
            self._usage_runtime,
            self._config.codebase_path,
            reasoning_effort=reasoning_effort,
        )
        if scope.is_file_review:
            return confirmer.confirm_paths_for_file(
                scope.target_file,
                scope.paths_to_confirm,
                scope.finalizer_graph,
                max_workers=max_workers,
            )
        return confirmer.confirm_paths(
            scope.paths_to_confirm,
            scope.finalizer_graph,
            max_workers=max_workers,
            progress_callback=progress_callback,
        )

    def _render_file_scope(self, scope: ReachabilityReviewScope, findings):
        result = {
            "file": scope.target_file,
            "file_path": scope.file_path,
            "reviews": [],
        }
        if findings:
            result["reviews"] = reviews_for_findings(
                findings,
                codebase_path=self._config.codebase_path,
            )
        return result

    @staticmethod
    def _file_review_paths_key(scope: ReachabilityReviewScope):
        return tuple(
            (path.source, path.sink, tuple(path.path or ()), path.sink_type)
            for path in scope.paths_to_confirm
        )

    def _file_review_cache_key(
        self,
        scope: ReachabilityReviewScope,
        *,
        model,
        reasoning_effort,
        max_paths_per_sink,
        max_path_length,
        domain_hints,
        domain_profiles,
    ):
        return (
            scope.target_file,
            str(model or ""),
            str(reasoning_effort or ""),
            int(max_paths_per_sink or 0),
            int(max_path_length or 0),
            str(scope.lens_profile or ""),
            repr(domain_hints or ()),
            repr(domain_profiles or ()),
            graph_fingerprint(scope.analysis_graph),
            graph_fingerprint(scope.finalizer_graph),
            self._file_review_paths_key(scope),
        )

    def annotate_findings_with_source_paths(
        self, findings, graph, *, max_path_length=DEFAULT_REACHABILITY_MAX_PATH_LENGTH
    ):
        return self._finalizer.annotate_findings_with_source_paths(
            findings,
            graph,
            max_path_length=max_path_length,
        )

    def get_codebase_graph_and_paths(
        self,
        *,
        max_path_length=DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
        progress_callback=None,
        source_functions=None,
        security_functions=None,
    ):
        return self._graphs.get_codebase_graph_and_paths(
            max_path_length=max_path_length,
            progress_callback=progress_callback,
            source_functions=source_functions,
            security_functions=security_functions,
        )

    def _ensure_supplementary(
        self,
        graph,
        *,
        scope_id="whole_graph",
        model,
        max_workers,
        progress_callback=None,
        reasoning_effort=None,
        lens_profile="all",
        domain_hints=None,
        domain_profiles=None,
    ):
        key = (
            str(scope_id or "whole_graph"),
            str(model or ""),
            str(reasoning_effort or ""),
            str(lens_profile or "all"),
            repr(domain_hints or ()),
            repr(domain_profiles or ()),
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
            reasoning_effort=reasoning_effort,
            domain_hints=domain_hints,
            domain_profiles=domain_profiles,
        ).analyze(
            graph,
            max_workers=max_workers,
            progress_callback=progress_callback,
            lens_profile=lens_profile,
        )
        self._supplementary_cache[key] = list(findings)
        return list(findings)

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
