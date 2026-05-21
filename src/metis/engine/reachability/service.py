# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Full-codebase tree-sitter reachability service."""

from __future__ import annotations

import json
import os

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from metis.utils import parse_json_output
from metis.reachability_settings import (
    DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
    DEFAULT_REACHABILITY_MAX_PATHS,
    DEFAULT_REACHABILITY_MAX_PATHS_PER_SINK,
    DEFAULT_REACHABILITY_WORKERS,
)

from .confirmer import VulnerabilityConfirmer
from .dedup import FINAL_DEDUP_SYSTEM_PROMPT
from .finding_finalizer import FindingFinalizer
from .graph_cache import ReachabilityGraphCache
from .graph_utils import (
    _copy_graph_nodes,
    graph_fingerprint,
    select_confirmation_paths,
)
from .llm_runner import _chat_model_kwargs
from .models import VulnerabilityFinding
from .supplementary import SupplementaryAnalyzer
from .file_focus import FileFocusBuilder
from .review_output import group_findings_as_reviews, reviews_for_findings


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

        focus = FileFocusBuilder(
            graph,
            max_path_length=max_path_length,
            max_incoming_paths=max_paths if max_paths > 0 else None,
        ).build(relative_target)
        source_to_file_paths = focus.incoming_paths
        outgoing_context_paths = focus.outgoing_context_paths
        if progress_callback:
            progress_callback(
                {
                    "event": "treesitter_file_paths_done",
                    "file": relative_target,
                    "paths": len(source_to_file_paths),
                    "source_to_file_paths": len(source_to_file_paths),
                    "outgoing_context_paths": len(outgoing_context_paths),
                    "focus_nodes": len(focus.node_names),
                }
            )

        model = confirmation_model or self._config.llama_query_model
        focus_graph = _copy_graph_nodes(graph, focus.node_names)
        if focus_graph.node_count() == 0:
            return None
        supplementary = self._ensure_supplementary(
            focus_graph,
            scope_id=relative_target,
            model=model,
            max_workers=max_workers,
            progress_callback=progress_callback,
            reasoning_effort=reasoning_effort,
            domain_hints=domain_hints,
            domain_profiles=domain_profiles,
        )

        confirmer = VulnerabilityConfirmer(
            self._llm_provider,
            model,
            self._usage_runtime,
            self._config.codebase_path,
            reasoning_effort=reasoning_effort,
        )

        path_findings = []
        if source_to_file_paths:
            path_findings.extend(
                confirmer.confirm_paths_for_file(
                    relative_target,
                    source_to_file_paths,
                    graph,
                    max_workers=max_workers,
                )
            )

        if progress_callback:
            progress_callback(
                {
                    "event": "treesitter_file_review_done",
                    "file": relative_target,
                    "supplementary_findings": len(supplementary),
                    "path_findings": len(path_findings),
                }
            )

        all_findings = [
            finding
            for finding in list(supplementary) + list(path_findings)
            if self._finalizer.participates_in_file(finding, relative_target, graph)
        ]
        deduped, _total, _removed = self._finalizer.finalize(
            all_findings,
            graph,
            max_paths_per_sink=max_paths_per_sink,
            max_path_length=max_path_length,
            target_file=relative_target,
            strict_file=True,
            duplicate_adjudicator=lambda candidates: self._adjudicate_duplicates(
                candidates,
                model=model,
                reasoning_effort=reasoning_effort,
            ),
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
        supplementary = self._ensure_supplementary(
            graph,
            scope_id="whole_graph",
            model=model,
            max_workers=max_workers,
            progress_callback=progress_callback,
            reasoning_effort=reasoning_effort,
            lens_profile=lens_profile,
            domain_hints=domain_hints,
            domain_profiles=domain_profiles,
        )
        path_findings = []
        if selected_paths:
            confirmer = VulnerabilityConfirmer(
                self._llm_provider,
                model,
                self._usage_runtime,
                self._config.codebase_path,
                reasoning_effort=reasoning_effort,
            )
            path_findings = confirmer.confirm_paths(
                selected_paths,
                graph,
                max_workers=max_workers,
                progress_callback=progress_callback,
            )

        deduped_findings, total_before, removed = self._finalizer.finalize(
            list(supplementary) + list(path_findings),
            graph,
            max_path_length=max_path_length,
            max_paths_per_sink=max_paths_per_sink,
            duplicate_adjudicator=lambda candidates: self._adjudicate_duplicates(
                candidates,
                model=model,
                reasoning_effort=reasoning_effort,
            ),
        )

        reviews = group_findings_as_reviews(
            deduped_findings,
            graph,
            codebase_path=self._config.codebase_path,
        )
        if progress_callback:
            progress_callback(
                {
                    "event": "treesitter_code_review_done",
                    "supplementary_findings": len(supplementary),
                    "path_findings": len(path_findings),
                    "raw_findings": total_before,
                    "deduped_findings": len(deduped_findings),
                    "removed_findings": removed,
                    "files": len(reviews),
                }
            )
        return reviews

    def annotate_findings_with_source_paths(
        self, findings, graph, *, max_path_length=DEFAULT_REACHABILITY_MAX_PATH_LENGTH
    ):
        return self._finalizer.annotate_findings_with_source_paths(
            findings,
            graph,
            max_path_length=max_path_length,
        )

    def _adjudicate_duplicates(self, candidates, *, model, reasoning_effort=None):
        if not candidates:
            return None
        try:
            chat = self._llm_provider.get_chat_model(
                model=model,
                max_tokens=2000,
                temperature=0.1,
                **_chat_model_kwargs(
                    self._usage_runtime,
                    reasoning_effort=reasoning_effort,
                ),
            )
            prompt = ChatPromptTemplate.from_messages(
                [
                    ("system", FINAL_DEDUP_SYSTEM_PROMPT),
                    ("user", "Candidate findings JSON:\n{candidate_findings}"),
                ]
            )
            raw = (prompt | chat | StrOutputParser()).invoke(
                {"candidate_findings": json.dumps(candidates, indent=2)}
            )
            parsed = parse_json_output(raw)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None

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
