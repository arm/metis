# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Full-codebase tree-sitter reachability service."""

from __future__ import annotations

import os
import re
import uuid
from collections import defaultdict
from pathlib import Path

from metis.utils import read_file_content

from ..reachability_common import (
    Deduplicator,
    FunctionNode,
    ReachabilityGraph,
    SourceRootedPathTracer,
    SupplementaryAnalyzer,
    VulnerabilityFinding,
    VulnerabilityConfirmer,
    _C_CPP_EXTS,
    _VULN_TO_CWE,
    _confidence_score,
    _normalise_vuln_type,
    _post_filter_findings,
    _read_line_context,
    _severity_title,
    _write_jsonl,
)
from .file_focus import FileFocusBuilder
from .finding_paths import FindingPathAnnotator

DEFAULT_OUTPUT_DIR = "metis_reachability_results"
DEFAULT_TREESITTER_OUTPUT_DIR = DEFAULT_OUTPUT_DIR
_AUTO_CONFIRMATION_MAX_PATHS = 48
_AUTO_CONFIRMATION_MAX_ENDPOINTS = 12
_AUTO_CONFIRMATION_PATHS_PER_ENDPOINT = 4


def c_cpp_files(files) -> list[str]:
    return [
        str(path)
        for path in files
        if os.path.splitext(str(path))[1].lower() in _C_CPP_EXTS
    ]


class TreeSitterReachabilityService:
    """Coordinate graph building, path tracing, supplementary passes, and output."""

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
            tuple[str, str, str, int], list[VulnerabilityFinding]
        ] = {}

    def get_c_cpp_files(self):
        return c_cpp_files(self._repository.get_code_files())

    def build_graph(self, files=None, *, progress_callback=None):
        selected = c_cpp_files(files if files is not None else self.get_c_cpp_files())
        return self._get_builder().build(
            selected,
            self._config.codebase_path,
            progress_callback=progress_callback,
        )

    def build_graph_interactive(self, files=None, *, progress_callback=None, **_kwargs):
        return self.build_graph(files, progress_callback=progress_callback)

    def trace_paths(self, graph, *, max_path_length=25):
        return SourceRootedPathTracer(
            graph, max_path_length=max_path_length
        ).find_all_paths()

    def select_confirmation_paths(self, paths, graph, *, max_paths=0):
        """Pick a bounded, representative set of source-rooted paths for AI confirmation.

        Full source-to-endpoint tracing can produce many near-equivalent terminal paths.
        The graph is still saved in full, but confirmation is capped by default because
        the supplementary audits already inspect the whole graph.
        """
        paths = self._dedupe_path_objects(paths)
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

    def confirm_paths(
        self,
        paths,
        graph,
        *,
        confirmation_model=None,
        max_workers=8,
        output_path=None,
        progress_callback=None,
        reasoning_effort=None,
    ):
        model = confirmation_model or self._config.llama_query_model
        return VulnerabilityConfirmer(
            self._llm_provider,
            model,
            self._usage_runtime,
            self._config.codebase_path,
            reasoning_effort=reasoning_effort,
        ).confirm_parallel(
            paths,
            graph,
            max_workers=max_workers,
            output_path=output_path,
            progress_callback=progress_callback,
        )

    def confirm_paths_streaming(
        self,
        paths,
        graph,
        *,
        confirmation_model=None,
        output_path=None,
        progress_callback=None,
        reasoning_effort=None,
    ):
        model = confirmation_model or self._config.llama_query_model
        return VulnerabilityConfirmer(
            self._llm_provider,
            model,
            self._usage_runtime,
            self._config.codebase_path,
            reasoning_effort=reasoning_effort,
        ).confirm_streaming(
            paths,
            graph,
            output_path=output_path,
            progress_callback=progress_callback,
        )

    def run_supplementary_analysis(
        self,
        graph,
        *,
        audit_model=None,
        strong_model=None,
        max_workers=8,
        progress_callback=None,
        reasoning_effort=None,
        analysis_profile="full",
    ):
        # Supplementary passes inspect the whole graph and usually provide the
        # final findings when path confirmation is skipped for large graphs.
        model = strong_model or self._config.llama_query_model
        audit = audit_model or model
        return SupplementaryAnalyzer(
            self._llm_provider,
            audit,
            model,
            self._usage_runtime,
            self._config.codebase_path,
            reasoning_effort=reasoning_effort,
        ).analyze(
            graph,
            max_workers=max_workers,
            progress_callback=progress_callback,
            analysis_profile=analysis_profile,
        )

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
        **_kwargs,
    ):
        abs_target, relative_target = self._normalize_target_file(file_path)
        graph = self._ensure_graph(progress_callback=progress_callback)
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
        focus_graph = self._build_graph_from_node_names(graph, focus.node_names)
        if focus_graph.node_count() == 0:
            return None
        supplementary = self._ensure_supplementary(
            focus_graph,
            scope_id=relative_target,
            model=model,
            max_workers=max_workers,
            progress_callback=progress_callback,
            reasoning_effort=reasoning_effort,
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

        deterministic_findings = self._deterministic_file_findings(
            relative_target,
            graph,
            source_to_file_paths,
        )
        if progress_callback:
            progress_callback(
                {
                    "event": "treesitter_file_review_done",
                    "file": relative_target,
                    "supplementary_findings": len(supplementary),
                    "path_findings": len(path_findings),
                    "deterministic_findings": len(deterministic_findings),
                }
            )

        all_findings = (
            self._findings_for_file(supplementary, relative_target, graph)
            + self._findings_for_file(path_findings, relative_target, graph)
            + deterministic_findings
        )
        all_findings = FindingPathAnnotator(
            graph,
            relative_target,
            max_path_length=max_path_length,
        ).annotate(all_findings)
        all_findings = self._strict_file_findings(all_findings)
        all_findings = _post_filter_findings(all_findings, self._config.codebase_path)
        if not all_findings:
            return {"file": relative_target, "file_path": abs_target, "reviews": []}

        deduped, _total, _removed = Deduplicator.deduplicate(
            all_findings,
            max_per_sink=max_paths_per_sink,
        )
        reviews = [
            self._finding_to_review(finding, graph=graph, target_file=relative_target)
            for finding in deduped
        ]
        reviews.sort(
            key=lambda item: (
                {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(
                    item.get("severity"), 4
                ),
                int(item.get("line_number") or 0),
                str(item.get("issue") or ""),
            )
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
        confirm_paths=True,
        analysis_profile="full",
        **_kwargs,
    ):
        graph, paths = self.get_codebase_graph_and_paths(
            max_path_length=max_path_length,
            progress_callback=progress_callback,
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

        # Convert direct function-level findings back into source-rooted paths
        # before filtering and legacy review JSON serialization.
        all_findings = self.annotate_findings_with_source_paths(
            list(supplementary) + list(path_findings),
            graph,
            max_path_length=max_path_length,
        )
        all_findings = _post_filter_findings(all_findings, self._config.codebase_path)
        deduped, total_before, removed = Deduplicator.deduplicate(
            all_findings,
            max_per_sink=max_paths_per_sink,
        )

        reviews = self._group_findings_as_reviews(deduped, graph)
        if progress_callback:
            progress_callback(
                {
                    "event": "treesitter_code_review_done",
                    "supplementary_findings": len(supplementary),
                    "path_findings": len(path_findings),
                    "raw_findings": total_before,
                    "deduped_findings": len(deduped),
                    "removed_findings": removed,
                    "files": len(reviews),
                }
            )
        return reviews

    def review_single_file_from_codebase(self, file_path, **kwargs):
        return self.review_file(file_path, **kwargs)

    def deduplicate_and_write(self, findings, output_path, *, max_paths_per_sink=3):
        filtered_findings = _post_filter_findings(findings, self._config.codebase_path)
        deduped, _total, _removed = Deduplicator.deduplicate(
            filtered_findings,
            max_per_sink=max_paths_per_sink,
        )
        _write_jsonl(output_path, deduped)
        return deduped, len(findings), len(findings) - len(deduped)

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

    def default_output_dir(self) -> Path:
        return (
            Path(os.path.abspath(self._config.codebase_path))
            / DEFAULT_TREESITTER_OUTPUT_DIR
        )

    def get_codebase_graph_and_paths(
        self, *, max_path_length=25, progress_callback=None
    ):
        """Return the cached codebase graph and traced paths for shared analysis."""
        max_path_length = int(max_path_length or 25)
        if (
            self._graph_cache is not None
            and self._paths_cache is not None
            and self._paths_cache_max_path_length == max_path_length
        ):
            return self._graph_cache, list(self._paths_cache)
        graph = self._ensure_graph(progress_callback=progress_callback)
        paths = self.trace_paths(graph, max_path_length=max_path_length)
        self._paths_cache = list(paths)
        self._paths_cache_max_path_length = max_path_length
        return graph, list(paths)

    def _dedupe_path_objects(self, paths):
        seen = set()
        selected = []
        for path in paths or []:
            key = (path.source, path.sink, tuple(path.path or []))
            if key in seen:
                continue
            seen.add(key)
            selected.append(path)
        return selected

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

    def _group_findings_as_reviews(self, findings, graph):
        by_file = defaultdict(list)
        for finding in findings:
            primary_file = (
                finding.primary_file or finding.sink_file or finding.source_file
            )
            if primary_file:
                by_file[primary_file].append(finding)

        reviews = []
        for target_file in sorted(by_file):
            items = [
                self._finding_to_review(finding, graph=graph, target_file=target_file)
                for finding in by_file[target_file]
            ]
            items.sort(
                key=lambda item: (
                    {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(
                        item.get("severity"), 4
                    ),
                    int(item.get("line_number") or 0),
                    str(item.get("issue") or ""),
                )
            )
            if items:
                reviews.append(
                    {
                        "file": target_file,
                        "file_path": os.path.join(
                            self._config.codebase_path, target_file
                        ),
                        "reviews": items,
                    }
                )
        return reviews

    def _ensure_graph(self, *, progress_callback=None):
        if self._graph_cache is not None:
            return self._graph_cache
        self._graph_cache = self.build_graph(progress_callback=progress_callback)
        return self._graph_cache

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
    ):
        key = (
            str(scope_id or "full"),
            str(model or ""),
            str(reasoning_effort or ""),
            str(analysis_profile or "full"),
            str(graph.node_count()),
            int(max_workers),
        )
        cached = self._supplementary_cache.get(key)
        if cached is not None:
            return list(cached)
        findings = self.run_supplementary_analysis(
            graph,
            audit_model=model,
            strong_model=model,
            max_workers=max_workers,
            progress_callback=progress_callback,
            reasoning_effort=reasoning_effort,
            analysis_profile=analysis_profile,
        )
        self._supplementary_cache[key] = list(findings)
        return list(findings)

    def _build_focus_graph(self, graph, target_paths):
        needed = self._path_node_names(target_paths)
        return self._build_graph_from_node_names(graph, needed)

    def _build_file_focus_graph(self, graph, target_file):
        needed = {node.unique_name for node in graph.get_file_nodes(target_file)}
        if not needed:
            return ReachabilityGraph()

        for node_name in list(needed):
            node = graph.get_node(node_name)
            if not node:
                continue
            needed.update(node.resolved_calls or [])
            for caller in graph.get_callers(node_name):
                needed.add(caller.unique_name)
        return self._build_graph_from_node_names(graph, needed)

    def _build_graph_from_node_names(self, graph, needed):
        focus = ReachabilityGraph()
        for unique_name in sorted(needed):
            node = graph.get_node(unique_name)
            if not node:
                continue
            focus.add_node(
                FunctionNode(
                    unique_name=node.unique_name,
                    file_path=node.file_path,
                    name=node.name,
                    line_number=node.line_number,
                    is_source=node.is_source,
                    is_sink=node.is_sink,
                    calls=list(node.calls or []),
                    resolved_calls=[],
                    source_reason=node.source_reason,
                    sink_type=node.sink_type,
                    sink_reason=node.sink_reason,
                )
            )
        needed_files = {node.file_path for node in focus.nodes.values()}
        for global_construct in graph.get_globals():
            if global_construct.file_path in needed_files:
                focus.add_global(global_construct)
        focus.resolve_all_calls()
        return focus

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

    def _paths_touching_file(self, graph, paths, target_file):
        selected = []
        for path in paths:
            for node_name in path.path:
                node = graph.get_node(node_name)
                if node and node.file_path == target_file:
                    selected.append(path)
                    break
        return selected

    def _split_paths_for_file(self, graph, paths, target_file):
        inbound, cross_file = [], []
        for path in paths:
            sink = graph.get_node(path.sink)
            if sink and sink.file_path == target_file:
                inbound.append(path)
            else:
                cross_file.append(path)
        return inbound, cross_file

    def _path_node_names(self, paths):
        names = set()
        for path in paths:
            names.update(path.path or [])
        return names

    def _finding_participates_in_file(self, finding, target_file, graph):
        if any(
            self._same_file(file_name, target_file)
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
            if node and self._same_file(node.file_path, target_file):
                return True
            if str(node_name or "").startswith(f"{target_file}::"):
                return True
        return False

    def _findings_for_file(self, findings, target_file, graph):
        selected = []
        for finding in findings:
            if self._finding_participates_in_file(finding, target_file, graph):
                selected.append(finding)
        return selected

    def _same_file(self, a, b):
        return str(a or "").replace("\\", "/") == str(b or "").replace("\\", "/")

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
            "deterministic_treesitter",
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

            if finding.analysis_type == "deterministic_treesitter":
                keep.append(finding)
                continue
            if vtype == "null_deref" and severity != "high":
                if finding.analysis_type != "classic_c_sink" or not any(
                    marker in text
                    for marker in ("before", "after", "lookup", "task_find")
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

    def _finding_to_review(self, finding, *, graph=None, target_file=""):
        line_number = int(
            finding.primary_line or finding.sink_line or finding.source_line or 1
        )
        vtype = _normalise_vuln_type(finding.vulnerability_type)
        primary_fn = finding.primary_function or finding.sink_function
        issue = (
            str(finding.description).strip()
            or f"{vtype.replace('_', ' ')} in {primary_fn}"
        )
        primary_file = finding.primary_file or finding.sink_file or finding.source_file
        reasoning_parts = []
        if primary_file:
            reasoning_parts.append(
                f"Primary location: {primary_file}:{line_number}"
                + (f" ({primary_fn})" if primary_fn else "")
            )
        if target_file and not self._same_file(primary_file, target_file):
            reasoning_parts.append(f"Reviewed file participates via: {target_file}")
        connected = self._connected_functions_for_finding(finding, graph, target_file)
        if connected:
            reasoning_parts.append(f"Connected functions: {', '.join(connected[:8])}")
        if str(finding.evidence or "").strip():
            reasoning_parts.append(str(finding.evidence).strip())
        if finding.path:
            reasoning_parts.append(f"Reachability path: {' -> '.join(finding.path)}")
        if str(finding.root_cause or "").strip():
            reasoning_parts.append(f"Root cause: {str(finding.root_cause).strip()}")
        if finding.analysis_type:
            reasoning_parts.append(f"Analysis type: {finding.analysis_type}")
        if finding.canonical_key:
            reasoning_parts.append(f"Canonical key: {finding.canonical_key}")
        target_file = primary_file
        return {
            "issue": issue,
            "line_number": line_number,
            "primary_file": primary_file,
            "primary_function": primary_fn,
            "analysis_type": finding.analysis_type,
            "path": list(finding.path or []),
            "code_snippet": (
                _read_line_context(
                    self._config.codebase_path, target_file, line_number, context=2
                )
                if target_file
                else ""
            ),
            "cwe": _VULN_TO_CWE.get(vtype),
            "severity": _severity_title(finding.severity, "Medium"),
            "confidence": _confidence_score(finding.confidence),
            "reasoning": "\n".join(reasoning_parts),
            "mitigation": str(finding.root_cause or "").strip(),
        }

    def _connected_functions_for_finding(self, finding, graph, target_file):
        if graph is None:
            return []
        connected = []
        seen = set()
        candidates = list(finding.path or [])
        candidates.extend(
            [
                finding.primary_function,
                finding.source_function,
                finding.sink_function,
            ]
        )
        for node_name in candidates:
            node = graph.get_node(node_name)
            if not node:
                continue
            for resolved_name in node.resolved_calls or []:
                resolved = graph.get_node(resolved_name)
                if not resolved:
                    continue
                if target_file and self._same_file(resolved.file_path, target_file):
                    continue
                if resolved.unique_name in seen:
                    continue
                seen.add(resolved.unique_name)
                connected.append(resolved.unique_name)
        return connected

    def _line_of(self, text, pattern, default=1):
        match = re.search(pattern, text, flags=re.MULTILINE | re.DOTALL)
        if not match:
            return default
        return text[: match.start()].count("\n") + 1

    def _function_for_line(self, graph, target_file, line):
        nodes = sorted(
            graph.get_file_nodes(target_file), key=lambda item: item.line_number
        )
        chosen = None
        for node in nodes:
            if node.line_number <= line:
                chosen = node
            else:
                break
        return chosen

    def _deterministic_finding(
        self,
        *,
        target_file,
        graph,
        line,
        vulnerability_type,
        severity,
        confidence,
        description,
        root_cause,
        evidence,
        token,
    ):
        fn = self._function_for_line(graph, target_file, line)
        fn_name = fn.unique_name if fn else f"{target_file}::unknown"
        fn_short = fn.name if fn else "unknown"
        return VulnerabilityFinding(
            id=uuid.uuid4().hex[:16],
            vulnerability_type=vulnerability_type,
            severity=severity,
            confidence=confidence,
            source_function=fn_name,
            source_file=target_file,
            source_line=line,
            sink_function=fn_name,
            sink_file=target_file,
            sink_line=line,
            path=[fn_name],
            description=description,
            root_cause=root_cause,
            evidence=evidence,
            analysis_type="deterministic_treesitter",
            primary_file=target_file,
            primary_function=fn_name,
            primary_line=line,
            canonical_key=f"{target_file}:{fn_short}:{vulnerability_type}:{token}",
        )

    def _deterministic_file_findings(self, target_file, graph, target_paths):
        content = read_file_content(
            os.path.join(self._config.codebase_path, target_file)
        )
        if not content:
            return []
        path_names = self._path_node_names(target_paths)
        findings = []

        def add_if_path_relevant(finding):
            if (
                not path_names
                or finding.primary_function in path_names
                or finding.source_function in path_names
            ):
                findings.append(finding)

        if re.search(
            r"\b\w+\s*\[\s*(?:MAX_[A-Z0-9_]+|\d+)\s*\]\s*;", content
        ) and re.search(r"\[[^\]]*&\s*0x0?f\s*\]", content, re.IGNORECASE):
            line = self._line_of(content, r"\[[^\]]*&\s*0x0?f\s*\]", 1)
            add_if_path_relevant(
                self._deterministic_finding(
                    target_file=target_file,
                    graph=graph,
                    line=line,
                    vulnerability_type="out_of_bounds",
                    severity="high",
                    confidence="high",
                    description="A masked protocol-controlled index can exceed the fixed array bounds.",
                    root_cause="The mask permits values 0-15, but the target array is smaller than that range.",
                    evidence="Array indexing uses an expression like flags & 0x0F against a fixed-size array.",
                    token="masked_index_exceeds_array",
                )
            )

        if (
            re.search(r"\(\s*\w+_t\s*\*\s*\)\s*store_get\s*\(", content)
            and "type_tag" not in content
        ):
            line = self._line_of(content, r"\(\s*\w+_t\s*\*\s*\)\s*store_get\s*\(", 1)
            add_if_path_relevant(
                self._deterministic_finding(
                    target_file=target_file,
                    graph=graph,
                    line=line,
                    vulnerability_type="type_confusion",
                    severity="high",
                    confidence="high",
                    description="A value returned from the generic store is cast to a concrete struct type without checking the stored type tag.",
                    root_cause="The code trusts a void* store lookup result as a specific object type without validating metadata such as type_tag.",
                    evidence="store_get(...) is directly cast to a typed pointer and dereferenced without a visible type check.",
                    token="store_get_cast_without_type_tag",
                )
            )

        if re.search(
            r"util_sanitize\s*\([^;]+payload_len[^;]*\)\s*;", content, re.DOTALL
        ) and re.search(r"data_len\s*=\s*payload_len\s*;", content):
            line = self._line_of(content, r"data_len\s*=\s*payload_len\s*;", 1)
            add_if_path_relevant(
                self._deterministic_finding(
                    target_file=target_file,
                    graph=graph,
                    line=line,
                    vulnerability_type="stale_length",
                    severity="high",
                    confidence="high",
                    description="The payload is sanitized before data_len is published, but the stored length remains the original pre-sanitization length.",
                    root_cause="Sanitization can shrink or rewrite the payload while callers continue to trust stale length metadata.",
                    evidence="util_sanitize(..., payload_len) is followed by msg->data_len = payload_len.",
                    token="sanitize_keeps_original_length",
                )
            )

        if re.search(r"memcpy\s*\([^;]+sizeof\s*\(\s*\w+_t\s*\)", content, re.DOTALL):
            line = self._line_of(
                content, r"memcpy\s*\([^;]+sizeof\s*\(\s*\w+_t\s*\)", 1
            )
            add_if_path_relevant(
                self._deterministic_finding(
                    target_file=target_file,
                    graph=graph,
                    line=line,
                    vulnerability_type="info_leak",
                    severity="high",
                    confidence="high",
                    description="The response copies an entire C struct, which can expose padding or uninitialized internal fields.",
                    root_cause="Whole-struct serialization is used instead of field-by-field serialization of initialized, intended output fields.",
                    evidence="memcpy copies sizeof(struct_type) bytes into a response buffer.",
                    token="whole_struct_response_copy",
                )
            )

        if re.search(
            r"title_len\s*=\s*\([^;]*\)\s*copied\s*\+\s*1\s*;", content
        ) and re.search(r"memcpy\s*\([^;]+title[^;]+title_len", content, re.DOTALL):
            line = self._line_of(
                content, r"title_len\s*=\s*\([^;]*\)\s*copied\s*\+\s*1\s*;", 1
            )
            add_if_path_relevant(
                self._deterministic_finding(
                    target_file=target_file,
                    graph=graph,
                    line=line,
                    vulnerability_type="stale_length",
                    severity="high",
                    confidence="high",
                    description="The stored title length includes an extra terminator byte and is later used as a serialization copy length.",
                    root_cause="A string length field is maintained as copied + 1, so later byte-oriented serialization can read one byte past the copied string data.",
                    evidence="task title length is assigned copied + 1 and later used in memcpy(..., t->title_len).",
                    token="title_len_copied_plus_one",
                )
            )

        return findings

    def _get_builder(self):
        if self._builder is None:
            from .builder import TreeSitterReachabilityGraphBuilder

            self._builder = TreeSitterReachabilityGraphBuilder()
        return self._builder
