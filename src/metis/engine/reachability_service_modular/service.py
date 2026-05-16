# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Full-codebase tree-sitter reachability service."""

from __future__ import annotations

import os

from ..reachability_common.confirmer import VulnerabilityConfirmer
from ..reachability_common.dedup import Deduplicator
from ..reachability_common.finding_normalization import _normalise_vuln_type
from ..reachability_common.graph_utils import (
    _copy_graph_nodes,
    _dedupe_paths,
    _same_file,
)
from ..reachability_common.models import VulnerabilityFinding
from ..reachability_common.post_filters import _post_filter_findings
from ..reachability_common.supplementary import SupplementaryAnalyzer
from ..reachability_common.tracing import SourceRootedPathTracer
from .file_focus import FileFocusBuilder
from .finding_paths import FindingPathAnnotator
from .review_output import group_findings_as_reviews, reviews_for_findings
from .c_family_rules import C_FAMILY_PLUGIN_NAMES

_AUTO_CONFIRMATION_MAX_PATHS = 48
_AUTO_CONFIRMATION_MAX_ENDPOINTS = 12
_AUTO_CONFIRMATION_PATHS_PER_ENDPOINT = 4


def _normalise_security_function_specs(raw):
    specs = {}

    def add(name, *, sink_type="other", reason="configured in metis.yaml"):
        key = str(name or "").strip()
        if not key:
            return
        specs[key.lower()] = {
            "sink_type": _normalise_vuln_type(sink_type or "other"),
            "reason": str(reason or "configured in metis.yaml").strip(),
        }

    if isinstance(raw, dict):
        items = raw.items()
    elif isinstance(raw, (list, tuple, set)):
        items = ((None, item) for item in raw)
    else:
        return specs

    for key, value in items:
        if isinstance(value, str):
            if key is None:
                add(value, sink_type="other")
            else:
                add(key, sink_type=value)
            continue
        if not isinstance(value, dict):
            add(key or value, sink_type="other")
            continue
        names = (
            value.get("names")
            or value.get("functions")
            or value.get("function_names")
            or value.get("name")
            or value.get("function")
            or value.get("function_name")
            or key
        )
        if isinstance(names, str):
            names = [names]
        for name in names or []:
            add(
                name,
                sink_type=value.get("sink_type") or value.get("type") or "other",
                reason=value.get("reason") or "configured in metis.yaml",
            )
    return specs


class TreeSitterReachabilityService:
    """Coordinate graph building, path tracing, supplementary lenses, and output."""

    def __init__(self, config, repository, llm_provider, usage_runtime):
        self._config = config
        self._repository = repository
        self._llm_provider = llm_provider
        self._usage_runtime = usage_runtime
        self._builder = None
        self._graph_cache = None
        self._paths_cache = None
        self._paths_cache_max_path_length = None
        self._supplementary_cache: dict[
            tuple[str | int, ...], list[VulnerabilityFinding]
        ] = {}

    def build_graph(self, files=None, *, progress_callback=None):
        selected = self._c_cpp_files(
            files if files is not None else self._repository.get_code_files()
        )
        return self._get_builder().build(
            selected,
            self._config.codebase_path,
            progress_callback=progress_callback,
        )

    def _c_cpp_files(self, files) -> list[str]:
        return [
            str(path)
            for path in files
            if self._repository.is_path_supported_by_plugins(
                str(path), C_FAMILY_PLUGIN_NAMES
            )
        ]

    def select_confirmation_paths(self, paths, graph, *, max_paths=0):
        """Pick a bounded, representative set of source-rooted paths for AI confirmation.

        Full source-to-endpoint tracing can produce many near-equivalent terminal paths.
        The graph is still saved in full, but confirmation is capped by default because
        the supplementary audits already inspect the whole graph.
        """
        paths = _dedupe_paths(paths)
        if max_paths and int(max_paths) > 0:
            return paths[: int(max_paths)]
        if len(paths) <= _AUTO_CONFIRMATION_MAX_PATHS:
            return paths

        indexed = list(enumerate(paths))
        indexed.sort(key=lambda item: self._confirmation_path_rank(item[1], graph))
        selected = []
        endpoint_counts = {}
        for _idx, path in indexed:
            endpoint = path.sink
            endpoint_count = endpoint_counts.get(endpoint, 0)
            if endpoint_count >= _AUTO_CONFIRMATION_PATHS_PER_ENDPOINT:
                continue
            if (
                len(endpoint_counts) >= _AUTO_CONFIRMATION_MAX_ENDPOINTS
                and endpoint not in endpoint_counts
            ):
                continue
            endpoint_counts[endpoint] = endpoint_count + 1
            selected.append((_idx, path))
            if len(selected) >= _AUTO_CONFIRMATION_MAX_PATHS:
                break

        selected.sort(key=lambda item: item[0])
        return [path for _idx, path in selected]

    def review_file(
        self,
        file_path,
        *,
        confirmation_model=None,
        max_workers=8,
        max_paths=0,
        max_paths_per_sink=3,
        max_path_length=25,
        progress_callback=None,
        reasoning_effort=None,
        security_functions=None,
        domain_hints=None,
        domain_profiles=None,
        **_kwargs,
    ):
        abs_target, relative_target = self._normalize_target_file(file_path)
        graph = self._ensure_graph(
            progress_callback=progress_callback,
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
                confirmer.confirm_for_file(
                    relative_target,
                    source_to_file_paths,
                    graph,
                    max_workers=max_workers,
                    progress_callback=progress_callback,
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
            if self._finding_participates_in_file(finding, relative_target, graph)
        ]
        deduped, _total, _removed = self._finalize_findings(
            all_findings,
            graph,
            max_paths_per_sink=max_paths_per_sink,
            max_path_length=max_path_length,
            target_file=relative_target,
            strict_file=True,
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
        max_workers=8,
        max_paths=0,
        max_paths_per_sink=3,
        max_path_length=25,
        progress_callback=None,
        reasoning_effort=None,
        security_functions=None,
        domain_hints=None,
        domain_profiles=None,
        confirm_paths=True,
        analysis_profile="full",
        **_kwargs,
    ):
        graph, paths = self.get_codebase_graph_and_paths(
            max_path_length=max_path_length,
            progress_callback=progress_callback,
            security_functions=security_functions,
        )
        if graph.node_count() == 0:
            return []
        selected_paths = []
        if confirm_paths:
            selected_paths = self.select_confirmation_paths(
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
            scope_id="full",
            model=model,
            max_workers=max_workers,
            progress_callback=progress_callback,
            reasoning_effort=reasoning_effort,
            analysis_profile=analysis_profile,
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
            path_findings = confirmer.confirm_parallel(
                selected_paths,
                graph,
                max_workers=max_workers,
                progress_callback=progress_callback,
            )

        deduped_findings, total_before, removed = self._finalize_findings(
            list(supplementary) + list(path_findings),
            graph,
            max_path_length=max_path_length,
            max_paths_per_sink=max_paths_per_sink,
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
        self, findings, graph, *, max_path_length=25
    ):
        annotated = []
        annotators = {}
        for finding in findings:
            target_file = (
                finding.primary_file or finding.sink_file or finding.source_file
            )
            if not target_file:
                annotated.append(finding)
                continue
            annotator = annotators.get(target_file)
            if annotator is None:
                annotator = FindingPathAnnotator(
                    graph,
                    target_file,
                    max_path_length=max_path_length,
                )
                annotators[target_file] = annotator
            annotated.append(annotator.annotate_one(finding))
        return annotated

    def get_codebase_graph_and_paths(
        self, *, max_path_length=25, progress_callback=None, security_functions=None
    ):
        """Return the cached codebase graph and traced paths for shared analysis."""
        max_path_length = int(max_path_length or 25)
        if self._graph_cache is not None:
            updated = self._annotate_configured_security_functions(
                self._graph_cache,
                security_functions,
                progress_callback=progress_callback,
            )
            if updated:
                self._paths_cache = None
                self._paths_cache_max_path_length = None
        if (
            self._graph_cache is not None
            and self._paths_cache is not None
            and self._paths_cache_max_path_length == max_path_length
        ):
            return self._graph_cache, list(self._paths_cache)
        graph = self._ensure_graph(
            progress_callback=progress_callback,
            security_functions=security_functions,
        )
        paths = SourceRootedPathTracer(
            graph, max_path_length=max_path_length
        ).find_all_paths()
        self._paths_cache = list(paths)
        self._paths_cache_max_path_length = max_path_length
        return graph, list(paths)

    def _confirmation_path_rank(self, path, graph):
        node_names = list(path.path or [])
        nodes = [graph.get_node(name) for name in node_names]
        nodes = [node for node in nodes if node is not None]
        endpoint = graph.get_node(path.sink)
        sink_count = sum(1 for node in nodes if node.is_sink)
        term_score = 0
        terms = (
            "auth",
            "permission",
            "login",
            "dispatch",
            "parse",
            "import",
            "export",
            "free",
            "close",
            "unref",
            "copy",
            "memcpy",
            "printf",
            "sanitize",
            "callback",
            "notify",
            "session",
            "store",
        )
        for node in nodes:
            haystack = " ".join(
                [
                    node.unique_name,
                    node.name,
                    node.sink_type,
                    node.sink_reason,
                    node.source_reason,
                ]
            ).lower()
            if any(term in haystack for term in terms):
                term_score += 1
        source = graph.get_node(path.source)
        return (
            -sink_count,
            -term_score,
            len(node_names),
            endpoint.file_path if endpoint else "",
            int(endpoint.line_number or 0) if endpoint else 0,
            source.file_path if source else "",
            int(source.line_number or 0) if source else 0,
            tuple(node_names),
        )

    def _finalize_findings(
        self,
        findings,
        graph,
        *,
        max_paths_per_sink,
        max_path_length=25,
        target_file="",
        strict_file=False,
    ):
        if target_file:
            findings = FindingPathAnnotator(
                graph,
                target_file,
                max_path_length=max_path_length,
            ).annotate(findings)
            if strict_file:
                findings = self._strict_file_findings(findings)
        else:
            # Convert direct function-level findings back into source-rooted paths
            # before filtering and legacy review JSON serialization.
            findings = self.annotate_findings_with_source_paths(
                findings,
                graph,
                max_path_length=max_path_length,
            )

        findings = _post_filter_findings(findings, self._config.codebase_path)
        if not findings:
            return [], 0, 0
        return Deduplicator.deduplicate(findings, max_per_sink=max_paths_per_sink)

    def _ensure_graph(self, *, progress_callback=None, security_functions=None):
        if self._graph_cache is not None:
            updated = self._annotate_configured_security_functions(
                self._graph_cache,
                security_functions,
                progress_callback=progress_callback,
            )
            if updated:
                self._paths_cache = None
                self._paths_cache_max_path_length = None
            return self._graph_cache
        graph = self.build_graph(progress_callback=progress_callback)
        self._annotate_configured_security_functions(
            graph,
            security_functions,
            progress_callback=progress_callback,
        )
        self._graph_cache = graph
        return self._graph_cache

    def _annotate_configured_security_functions(
        self, graph, security_functions, *, progress_callback=None
    ):
        specs = _normalise_security_function_specs(security_functions)
        if not specs:
            return 0
        updated = 0
        for node in graph.nodes.values():
            if node.is_sink:
                continue
            matched_calls = [
                str(call)
                for call in node.calls or []
                if str(call or "").lower() in specs
            ]
            if not matched_calls:
                continue
            spec = specs[str(matched_calls[0]).lower()]
            node.is_sink = True
            node.sink_type = spec["sink_type"]
            node.sink_reason = f"calls configured security function {matched_calls[0]}: {spec['reason']}"
            updated += 1

        if updated and progress_callback:
            progress_callback(
                {"event": "configured_security_functions_done", "sinks": updated}
            )
        return updated

    def _ensure_supplementary(
        self,
        graph,
        *,
        scope_id="full",
        model,
        max_workers,
        progress_callback=None,
        reasoning_effort=None,
        analysis_profile="full",
        domain_hints=None,
        domain_profiles=None,
    ):
        key = (
            str(scope_id or "full"),
            str(model or ""),
            str(reasoning_effort or ""),
            str(analysis_profile or "full"),
            repr(domain_hints or ()),
            repr(domain_profiles or ()),
            str(graph.node_count()),
            int(max_workers),
        )
        cached = self._supplementary_cache.get(key)
        if cached is not None:
            return list(cached)
        findings = SupplementaryAnalyzer(
            self._llm_provider,
            model,
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
            analysis_profile=analysis_profile,
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

    def _finding_participates_in_file(self, finding, target_file, graph):
        if any(
            _same_file(file_name, target_file)
            for file_name in (
                finding.primary_file,
                finding.source_file,
                finding.sink_file,
            )
        ):
            return True
        for node_name in list(finding.path or []) + [
            finding.primary_function,
            finding.source_function,
            finding.sink_function,
        ]:
            node = graph.get_node(node_name) if graph is not None else None
            if node and _same_file(node.file_path, target_file):
                return True
            if str(node_name or "").startswith(f"{target_file}::"):
                return True
        return False

    def _strict_file_findings(self, findings):
        keep = []
        important_types = {
            "buffer_overflow",
            "out_of_bounds",
            "use_after_free",
            "double_free",
            "double_close",
            "format_string",
            "integer_overflow",
            "type_confusion",
            "info_leak",
            "stale_length",
            "missing_auth",
            "permission_mismatch",
            "refcount_imbalance",
            "accounting_drift",
            "null_deref",
        }
        important_analysis = {
            "reachability",
            "lifecycle",
            "ownership",
            "targeted_callback_lifecycle",
            "targeted_refcount",
            "targeted_permission",
            "classic_c_sink",
            "counter_symmetry",
        }
        low_signal_null_markers = (
            "caller-supplied",
            "pointer parameter",
            "parameters before",
            "localtime",
            "calloc",
            "allocation result",
        )
        for finding in findings:
            vtype = _normalise_vuln_type(finding.vulnerability_type)
            severity = str(finding.severity or "").lower()
            confidence = str(finding.confidence or "").lower()
            text = " ".join(
                [
                    str(finding.description or ""),
                    str(finding.root_cause or ""),
                    str(finding.evidence or ""),
                ]
            ).lower()

            if vtype == "null_deref" and severity != "high":
                if finding.analysis_type != "classic_c_sink" or not any(
                    marker in text for marker in ("before", "after", "lookup")
                ):
                    if any(marker in text for marker in low_signal_null_markers):
                        continue
            if severity == "high":
                keep.append(finding)
                continue
            if confidence == "high" and (
                vtype in important_types or finding.analysis_type in important_analysis
            ):
                keep.append(finding)
        return keep

    def _get_builder(self):
        if self._builder is None:
            from .builder import TreeSitterReachabilityGraphBuilder

            self._builder = TreeSitterReachabilityGraphBuilder()
        return self._builder
