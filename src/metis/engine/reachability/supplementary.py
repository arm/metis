# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import logging
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from metis.reachability_settings import DEFAULT_REACHABILITY_WORKERS
from metis.usage import submit_with_current_context
from metis.engine.llm_runner import invoke_langchain_json_prompt_with_retry

from .llm_runner import reachability_response_payload
from .domain_hints import format_domain_hints_for_prompt, normalize_domain_hints
from .graph_utils import _build_reverse_edges, _chunked, _emit_progress, _node_sort_key
from .lock_order import _extract_lock_conflicts
from .models import ReachabilityFindingResponseModel
from .supplementary_lenses import (
    _COMBINED_GRAPH_LENS_NOTES,
    _FULL_LENS_SPECS,
    _REVIEW_LENS_NAMES,
)
from .supplementary_parsing import _parse_combined, _parse_intra, _parse_semantic
from .supplementary_prompts import (
    _COMBINED_GRAPH_SYS,
    _COMBINED_GRAPH_USR,
    _INTRA_SYS,
    _INTRA_USR,
)
from .source_context import (
    _build_file_grouped_chunks,
    _build_file_grouped_node_chunks,
    _build_globals_code,
    _read_function_body,
)

logger = logging.getLogger("metis")


def _add_node_context(
    graph, reverse_edges, selected, unique_name, *, with_neighbors=False
):
    node = graph.get_node(unique_name)
    if not node:
        return
    selected[node.unique_name] = node
    if not with_neighbors:
        return
    for callee_name in node.resolved_calls or []:
        callee = graph.get_node(callee_name)
        if callee:
            selected[callee.unique_name] = callee
    for caller_name in reverse_edges.get(node.unique_name, []):
        caller = graph.get_node(caller_name)
        if caller:
            selected[caller.unique_name] = caller


def _run_chunked_lens(chunks, worker, *, max_workers, event_prefix):
    if len(chunks) == 1:
        return list(worker(*chunks[0]))
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(chunks)))) as ex:
        futs = [
            submit_with_current_context(ex, worker, nodes, text)
            for nodes, text in chunks
        ]
        for fut in as_completed(futs):
            try:
                results.extend(fut.result())
            except Exception as e:
                logger.warning("%s chunk fail: %s", event_prefix, e)
    return results


class SupplementaryAnalyzer:
    def __init__(
        self,
        llm_provider,
        model,
        usage_runtime,
        codebase_path,
        audit_max_tokens=8192,
        strong_max_tokens=16384,
        reasoning_effort=None,
        domain_hints=None,
        domain_profiles=None,
    ):
        self._p = llm_provider
        self._m = model
        self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path)
        self._at = audit_max_tokens
        self._st = strong_max_tokens
        self._reasoning_effort = reasoning_effort
        self._domain_hints = normalize_domain_hints(domain_hints, domain_profiles)
        self._domain_keywords = self._domain_hints["keywords"]
        self._domain_prompt_hints = format_domain_hints_for_prompt(self._domain_hints)

    def _with_domain_hints(self, prompt):
        return (
            f"{prompt}\n\n{self._domain_prompt_hints}"
            if self._domain_prompt_hints
            else prompt
        )

    def analyze(
        self,
        graph,
        *,
        max_workers=DEFAULT_REACHABILITY_WORKERS,
        progress_callback=None,
        lens_profile="all",
    ):
        profile = str(lens_profile or "all").lower()
        lens_specs = (
            [spec for spec in _FULL_LENS_SPECS if spec.name in _REVIEW_LENS_NAMES]
            if profile == "review"
            else list(_FULL_LENS_SPECS)
        )
        if not lens_specs:
            return []
        findings = []
        combined_specs = [spec for spec in lens_specs if spec.runs_as_combined_graph()]
        lens_jobs = [spec for spec in lens_specs if not spec.runs_as_combined_graph()]
        if combined_specs:
            lens_jobs.insert(0, tuple(combined_specs))
        worker_budget = max(1, int(max_workers or 1))
        lens_parallelism = max(1, min(len(lens_jobs), worker_budget, 8))
        lens_workers = max(1, worker_budget // lens_parallelism)

        def _job_name(job):
            return "combined_graph_lenses" if isinstance(job, tuple) else job.name

        def _run_lens(job):
            try:
                if isinstance(job, tuple):
                    return self._run_combined_graph_lenses(
                        job, graph, lens_workers, progress_callback
                    )
                return self._run_lens_spec(job, graph, lens_workers, progress_callback)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                name = _job_name(job)
                logger.warning("%s lens fail: %s", name, exc)
                _emit_progress(
                    progress_callback,
                    f"{name}_error",
                    error=f"{type(exc).__name__}: {exc}",
                )
                return []

        if lens_parallelism == 1:
            for job in lens_jobs:
                findings.extend(_run_lens(job))
        else:
            with ThreadPoolExecutor(max_workers=lens_parallelism) as executor:
                futures = {
                    submit_with_current_context(executor, _run_lens, job): _job_name(
                        job
                    )
                    for job in lens_jobs
                }
                for future in as_completed(futures):
                    findings.extend(future.result())
        if progress_callback:
            by_type = defaultdict(int)
            for f in findings:
                by_type[f.analysis_type] += 1
            _emit_progress(
                progress_callback,
                "supplementary_done",
                **dict(by_type),
                total=len(findings),
            )
        return findings

    def _combined_prompt_variables(self, analysis_types, code):
        analysis_types = list(analysis_types)
        lens_instructions = "\n".join(
            _COMBINED_GRAPH_LENS_NOTES.get(analysis_type, analysis_type)
            for analysis_type in analysis_types
        )
        if self._domain_prompt_hints:
            lens_instructions = f"{lens_instructions}\n\n{self._domain_prompt_hints}"
        return {
            "all_functions_code": code,
            "allowed_analysis_types": ", ".join(analysis_types),
            "lens_instructions": lens_instructions,
        }

    def _invoke_findings(
        self, system_prompt, user_prompt, variables, *, max_tokens=None
    ):
        return invoke_langchain_json_prompt_with_retry(
            self._p,
            self._u,
            model=self._m,
            max_tokens=max_tokens or self._st,
            temperature=0.1,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            variables=variables,
            parse=reachability_response_payload,
            logger=logger,
            label="Supplementary reachability analysis",
            batch_size=1,
            invalid_message="expected findings list",
            final_keep_message="keeping this supplementary batch empty",
            response_model=ReachabilityFindingResponseModel,
            reasoning_effort=self._reasoning_effort,
        )

    def _run_combined_graph_lenses(self, specs, graph, max_workers, cb):
        event_name = "combined_graph_lenses"
        analysis_types = [spec.analysis_type for spec in specs]
        fns = list(graph.nodes.values())
        if not fns:
            return []
        _emit_progress(
            cb,
            f"{event_name}_start",
            functions=len(fns),
            lenses=[spec.name for spec in specs],
        )
        chunks = [
            (fns, chunk)
            for chunk in _build_file_grouped_chunks(
                self._cb, fns, max_total_chars=60000, per_fn_chars=3000
            )
        ]
        if not chunks:
            return []
        globals_code = _build_globals_code(graph)
        if globals_code:
            chunks = [
                (nodes, f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{chunk}")
                for nodes, chunk in chunks
            ]

        def _run_chunk(chunk_nodes, code_chunk):
            raw = self._invoke_findings(
                _COMBINED_GRAPH_SYS,
                _COMBINED_GRAPH_USR,
                self._combined_prompt_variables(analysis_types, code_chunk),
            )
            return _parse_combined(raw, chunk_nodes, frozenset(analysis_types))

        results = _run_chunked_lens(
            chunks, _run_chunk, max_workers=max_workers, event_prefix=event_name
        )
        _emit_progress(cb, f"{event_name}_done", findings=len(results))
        return results

    def _run_lens_spec(self, spec, graph, max_workers, cb):
        if spec.uses_method_runner():
            return getattr(self, spec.method_name)(graph, max_workers, cb)
        if spec.uses_candidate_runner():
            return self._run_candidate_lens(
                graph,
                spec,
                max_workers,
                cb,
            )
        raise ValueError(f"unknown supplementary lens kind: {spec.kind}")

    def _lens_intra(self, graph, max_workers, cb):
        targets = self._structural_candidate_nodes(graph)
        if not targets:
            return []
        groups = defaultdict(list)
        for t in targets:
            groups[t.file_path].append(t)
        _emit_progress(
            cb, "intra_audit_start", files=len(groups), functions=len(targets)
        )
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {
                submit_with_current_context(ex, self._audit_file, fp, fns): fp
                for fp, fns in groups.items()
            }
            done = 0
            for fut in as_completed(futs):
                fp = futs[fut]
                done += 1
                try:
                    results.extend(fut.result())
                except Exception as e:
                    logger.warning("Intra audit fail %s: %s", fp, e)
                _emit_progress(
                    cb,
                    "intra_audit_progress",
                    completed=done,
                    total=len(groups),
                    file=fp,
                )
        return results

    def _structural_candidate_nodes(self, graph, *, sinks_only=False):
        reverse_edges = _build_reverse_edges(
            graph, lambda item: _node_sort_key(graph, item)
        )
        selected = {}

        for node in graph.nodes.values():
            if node.is_sink or (node.is_source and not sinks_only):
                _add_node_context(
                    graph,
                    reverse_edges,
                    selected,
                    node.unique_name,
                    with_neighbors=not sinks_only,
                )

        if not sinks_only:
            for global_construct in graph.get_globals():
                for ref in global_construct.referenced_functions:
                    for unique_name in graph.name_index.get(ref, []):
                        _add_node_context(
                            graph,
                            reverse_edges,
                            selected,
                            unique_name,
                            with_neighbors=True,
                        )

            for node in graph.nodes.values():
                degree = len(node.resolved_calls or []) + len(
                    reverse_edges.get(node.unique_name, [])
                )
                if degree >= 2:
                    _add_node_context(graph, reverse_edges, selected, node.unique_name)

            if self._domain_keywords:
                for node in graph.nodes.values():
                    text = f"{node.name} {' '.join(node.calls or [])}".lower()
                    if any(keyword in text for keyword in self._domain_keywords):
                        _add_node_context(
                            graph,
                            reverse_edges,
                            selected,
                            node.unique_name,
                            with_neighbors=True,
                        )

        return sorted(
            selected.values(),
            key=lambda node: (node.file_path, int(node.line_number or 0), node.name),
        )

    def _audit_file(self, file_path, functions):
        bodies = []
        for fn in functions:
            b = _read_function_body(self._cb, fn, 4096)
            if b:
                bodies.append(f"--- {fn.unique_name} (line {fn.line_number}) ---\n{b}")
        if not bodies:
            return []
        raw = self._invoke_findings(
            self._with_domain_hints(_INTRA_SYS),
            _INTRA_USR,
            {"file_path": file_path, "functions_code": "\n\n".join(bodies)},
            max_tokens=self._at,
        )
        return _parse_intra(raw, functions)

    def _run_candidate_lens(
        self,
        graph,
        spec,
        max_workers,
        cb,
    ):
        candidates = self._structural_candidate_nodes(
            graph,
            sinks_only=spec.sinks_only,
        )
        if not candidates:
            return []
        _emit_progress(cb, f"{spec.name}_start", functions=len(candidates))
        chunks = _build_file_grouped_node_chunks(
            self._cb,
            candidates,
            max_total_chars=spec.max_total_chars,
            per_fn_chars=spec.per_fn_chars,
        )
        if not chunks:
            return []

        def _run_chunk(chunk_nodes, code_chunk):
            raw = self._invoke_findings(
                self._with_domain_hints(spec.sys_prompt),
                _INTRA_USR,
                {
                    "file_path": "candidate functions",
                    "functions_code": code_chunk,
                },
            )
            if spec.parses_semantic_entries():
                return _parse_semantic(
                    raw,
                    chunk_nodes,
                    analysis_type=spec.analysis_type,
                )
            return _parse_intra(raw, chunk_nodes, analysis_type=spec.analysis_type)

        results = _run_chunked_lens(
            chunks, _run_chunk, max_workers=max_workers, event_prefix=spec.name
        )
        _emit_progress(cb, f"{spec.name}_done", findings=len(results))
        return results

    def _lens_global_lifecycle(self, graph, max_workers, cb):
        globals_ = graph.get_globals()
        if not globals_:
            return []
        nodes_by_unique = {}
        reverse_edges = _build_reverse_edges(
            graph, lambda item: _node_sort_key(graph, item)
        )

        for g in globals_:
            for ref in g.referenced_functions:
                for unique_name in graph.name_index.get(ref, []):
                    _add_node_context(
                        graph,
                        reverse_edges,
                        nodes_by_unique,
                        unique_name,
                        with_neighbors=True,
                    )
            for node in graph.get_file_nodes(g.file_path):
                if node.is_source or node.is_sink:
                    _add_node_context(
                        graph,
                        reverse_edges,
                        nodes_by_unique,
                        node.unique_name,
                        with_neighbors=True,
                    )

        nodes = list(nodes_by_unique.values())
        nodes = sorted(nodes, key=lambda n: (n.file_path, n.line_number, n.name))
        if not nodes:
            return []
        _emit_progress(
            cb, "global_lifecycle_start", globals=len(globals_), functions=len(nodes)
        )
        chunks = _build_file_grouped_node_chunks(
            self._cb, nodes, max_total_chars=50000, per_fn_chars=4000
        )
        globals_code = _build_globals_code(graph, max_chars=30000)

        def _run_chunk(chunk_nodes, code_chunk):
            code = f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{code_chunk}"
            raw = self._invoke_findings(
                _COMBINED_GRAPH_SYS,
                _COMBINED_GRAPH_USR,
                self._combined_prompt_variables(["global_lifecycle"], code),
            )
            return _parse_semantic(raw, chunk_nodes, analysis_type="global_lifecycle")

        results = _run_chunked_lens(
            chunks,
            _run_chunk,
            max_workers=max_workers,
            event_prefix="Global lifecycle",
        )
        _emit_progress(cb, "global_lifecycle_done", findings=len(results))
        return results

    def _lens_lock_order(self, graph, _max_workers, cb):
        conflicts = _extract_lock_conflicts(graph, self._cb)
        if not conflicts:
            return []
        _emit_progress(cb, "lock_order_extraction_start", conflicts=len(conflicts))
        results = []
        for batch in _chunked(conflicts, 8):
            nodes = []
            seen = set()
            lines = ["== LOCK ORDER CANDIDATES =="]
            for i, (a, b, node_a, line_a, node_b, line_b) in enumerate(batch):
                lines.append(
                    f"Conflict {i}: {a} -> {b} in {node_a.unique_name} line {line_a}; "
                    f"{b} -> {a} in {node_b.unique_name} line {line_b}"
                )
                for node in (node_a, node_b):
                    if node.unique_name not in seen:
                        seen.add(node.unique_name)
                        nodes.append(node)
            body_chunks = _build_file_grouped_chunks(
                self._cb, nodes, max_total_chars=50000, per_fn_chars=5000
            )
            code = (
                "\n".join(lines)
                + "\n\n== RELEVANT FUNCTION BODIES ==\n"
                + "\n\n".join(body_chunks)
            )
            raw = self._invoke_findings(
                _COMBINED_GRAPH_SYS,
                _COMBINED_GRAPH_USR,
                self._combined_prompt_variables(["lock_order_extraction"], code),
            )
            results.extend(
                _parse_semantic(raw, nodes, analysis_type="lock_order_extraction")
            )
        _emit_progress(cb, "lock_order_extraction_done", findings=len(results))
        return results
