# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections import defaultdict
import logging

from .graph_utils import _build_reverse_edges, _chunked, _emit_progress, _node_sort_key
from .lock_order import _extract_lock_conflicts
from .progress import ReachabilityProgress as Progress
from .source_context import (
    _build_file_grouped_chunks,
    _build_file_grouped_node_chunks,
    _build_globals_code,
    _read_function_body,
)
from .supplementary_parsing import _parse_combined, _parse_intra, _parse_semantic
from .supplementary_prompts import (
    _COMBINED_GRAPH_SYS,
    _COMBINED_GRAPH_USR,
    _INTRA_SYS,
    _INTRA_USR,
)
from .workers import run_reachability_jobs

logger = logging.getLogger("metis")


def run_chunked_lens(chunks, worker, *, max_workers, event_prefix):
    results = []
    chunk_results = run_reachability_jobs(
        chunks,
        lambda chunk: list(worker(*chunk)),
        max_workers=max_workers,
        label=f"{event_prefix} chunk",
        result_key=lambda chunk: f"{len(chunk[0])} functions",
    )
    for chunk_result in chunk_results:
        results.extend(chunk_result)
    return results


def run_combined_graph_lenses(analyzer, specs, graph, options):
    event_name = "combined_graph_lenses"
    cb = options.progress_callback
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
            analyzer._cb, fns, max_total_chars=60000, per_fn_chars=3000
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
        raw = analyzer._invoke_findings(
            _COMBINED_GRAPH_SYS,
            _COMBINED_GRAPH_USR,
            analyzer._combined_prompt_variables(analysis_types, code_chunk),
        )
        return _parse_combined(raw, chunk_nodes, frozenset(analysis_types))

    results = run_chunked_lens(
        chunks,
        _run_chunk,
        max_workers=options.max_workers,
        event_prefix=event_name,
    )
    _emit_progress(cb, f"{event_name}_done", findings=len(results))
    return results


def run_intra_lens(analyzer, graph, options):
    cb = options.progress_callback
    targets = structural_candidate_nodes(analyzer, graph)
    if not targets:
        return []
    groups = defaultdict(list)
    for target in targets:
        groups[target.file_path].append(target)
    _emit_progress(
        cb,
        Progress.INTRA_AUDIT_START,
        files=len(groups),
        functions=len(targets),
    )
    results = []
    audit_results = run_reachability_jobs(
        list(groups.items()),
        lambda item: audit_file(analyzer, item[0], item[1]),
        max_workers=options.max_workers,
        label="Intra audit",
        result_key=lambda item: item[0],
        on_complete=lambda fp, done, total: _emit_progress(
            cb,
            Progress.INTRA_AUDIT_PROGRESS,
            completed=done,
            total=total,
            file=fp,
        ),
    )
    for audit_result in audit_results:
        results.extend(audit_result)
    return results


def run_candidate_lens(analyzer, graph, spec, options):
    cb = options.progress_callback
    candidates = structural_candidate_nodes(
        analyzer,
        graph,
        sinks_only=spec.sinks_only,
    )
    if not candidates:
        return []
    _emit_progress(cb, f"{spec.name}_start", functions=len(candidates))
    chunks = _build_file_grouped_node_chunks(
        analyzer._cb,
        candidates,
        max_total_chars=spec.max_total_chars,
        per_fn_chars=spec.per_fn_chars,
    )
    if not chunks:
        return []

    def _run_chunk(chunk_nodes, code_chunk):
        raw = analyzer._invoke_findings(
            analyzer._with_domain_hints(spec.sys_prompt),
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

    results = run_chunked_lens(
        chunks,
        _run_chunk,
        max_workers=options.max_workers,
        event_prefix=spec.name,
    )
    _emit_progress(cb, f"{spec.name}_done", findings=len(results))
    return results


def run_global_lifecycle_lens(analyzer, graph, options):
    cb = options.progress_callback
    globals_ = graph.get_globals()
    if not globals_:
        return []
    nodes_by_unique = {}
    reverse_edges = _build_reverse_edges(
        graph, lambda item: _node_sort_key(graph, item)
    )

    for global_construct in globals_:
        for ref in global_construct.referenced_functions:
            for unique_name in graph.name_index.get(ref, []):
                add_node_context(
                    graph,
                    reverse_edges,
                    nodes_by_unique,
                    unique_name,
                    with_neighbors=True,
                )
        for node in graph.get_file_nodes(global_construct.file_path):
            if node.is_source or node.is_sink:
                add_node_context(
                    graph,
                    reverse_edges,
                    nodes_by_unique,
                    node.unique_name,
                    with_neighbors=True,
                )

    nodes = list(nodes_by_unique.values())
    nodes = sorted(
        nodes, key=lambda node: (node.file_path, node.line_number, node.name)
    )
    if not nodes:
        return []
    _emit_progress(
        cb,
        Progress.GLOBAL_LIFECYCLE_START,
        globals=len(globals_),
        functions=len(nodes),
    )
    chunks = _build_file_grouped_node_chunks(
        analyzer._cb, nodes, max_total_chars=50000, per_fn_chars=4000
    )
    globals_code = _build_globals_code(graph, max_chars=30000)

    def _run_chunk(chunk_nodes, code_chunk):
        code = f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{code_chunk}"
        raw = analyzer._invoke_findings(
            _COMBINED_GRAPH_SYS,
            _COMBINED_GRAPH_USR,
            analyzer._combined_prompt_variables(["global_lifecycle"], code),
        )
        return _parse_semantic(raw, chunk_nodes, analysis_type="global_lifecycle")

    results = run_chunked_lens(
        chunks,
        _run_chunk,
        max_workers=options.max_workers,
        event_prefix="Global lifecycle",
    )
    _emit_progress(cb, Progress.GLOBAL_LIFECYCLE_DONE, findings=len(results))
    return results


def run_lock_order_lens(analyzer, graph, options):
    cb = options.progress_callback
    conflicts = _extract_lock_conflicts(graph, analyzer._cb)
    if not conflicts:
        return []
    _emit_progress(
        cb,
        Progress.LOCK_ORDER_EXTRACTION_START,
        conflicts=len(conflicts),
    )
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
            analyzer._cb, nodes, max_total_chars=50000, per_fn_chars=5000
        )
        code = (
            "\n".join(lines)
            + "\n\n== RELEVANT FUNCTION BODIES ==\n"
            + "\n\n".join(body_chunks)
        )
        raw = analyzer._invoke_findings(
            _COMBINED_GRAPH_SYS,
            _COMBINED_GRAPH_USR,
            analyzer._combined_prompt_variables(["lock_order_extraction"], code),
        )
        results.extend(
            _parse_semantic(raw, nodes, analysis_type="lock_order_extraction")
        )
    _emit_progress(cb, Progress.LOCK_ORDER_EXTRACTION_DONE, findings=len(results))
    return results


def structural_candidate_nodes(analyzer, graph, *, sinks_only=False):
    reverse_edges = _build_reverse_edges(
        graph, lambda item: _node_sort_key(graph, item)
    )
    selected = {}

    for node in graph.nodes.values():
        if node.is_sink or (node.is_source and not sinks_only):
            add_node_context(
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
                    add_node_context(
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
                add_node_context(graph, reverse_edges, selected, node.unique_name)

        if analyzer._domain_keywords:
            for node in graph.nodes.values():
                text = f"{node.name} {' '.join(node.calls or [])}".lower()
                if any(keyword in text for keyword in analyzer._domain_keywords):
                    add_node_context(
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


def audit_file(analyzer, file_path, functions):
    bodies = []
    for function in functions:
        body = _read_function_body(analyzer._cb, function, 4096)
        if body:
            bodies.append(
                f"--- {function.unique_name} (line {function.line_number}) ---\n{body}"
            )
    if not bodies:
        return []
    raw = analyzer._invoke_findings(
        analyzer._with_domain_hints(_INTRA_SYS),
        _INTRA_USR,
        {"file_path": file_path, "functions_code": "\n\n".join(bodies)},
        max_tokens=analyzer._at,
    )
    return _parse_intra(raw, functions)


def add_node_context(
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
