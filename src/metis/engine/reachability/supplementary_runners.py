# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections import defaultdict
from itertools import chain

from .graph_utils import _build_reverse_edges, _chunked, _emit_progress, _node_sort_key
from .limits import (
    SOURCE_CONTEXT_MAX_TOTAL_CHARS,
    SOURCE_CONTEXT_PER_FUNCTION_CHARS,
    SUPPLEMENTARY_GLOBAL_LIFECYCLE_MAX_TOTAL_CHARS,
    SUPPLEMENTARY_GLOBAL_LIFECYCLE_PER_FUNCTION_CHARS,
    SUPPLEMENTARY_GLOBALS_MAX_CHARS,
    SUPPLEMENTARY_INTRA_FUNCTION_BODY_CHARS,
    SUPPLEMENTARY_LOCK_ORDER_BATCH_SIZE,
    SUPPLEMENTARY_LOCK_ORDER_MAX_TOTAL_CHARS,
    SUPPLEMENTARY_LOCK_ORDER_PER_FUNCTION_CHARS,
)
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


def _run_chunked_lens(chunks, worker, *, max_workers, event_prefix):
    chunk_results = run_reachability_jobs(
        chunks,
        lambda chunk: list(worker(*chunk)),
        max_workers=max_workers,
        label=f"{event_prefix} chunk",
        result_key=lambda chunk: f"{len(chunk[0])} functions",
    )
    return list(chain.from_iterable(chunk_results))


def _invoke_combined(analyzer, analysis_types, code):
    return analyzer._invoke_findings(
        _COMBINED_GRAPH_SYS,
        _COMBINED_GRAPH_USR,
        analyzer._combined_prompt_variables(analysis_types, code),
    )


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
            analyzer._cb,
            fns,
            max_total_chars=SOURCE_CONTEXT_MAX_TOTAL_CHARS,
            per_fn_chars=SOURCE_CONTEXT_PER_FUNCTION_CHARS,
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
        raw = _invoke_combined(analyzer, analysis_types, code_chunk)
        return _parse_combined(raw, chunk_nodes, frozenset(analysis_types))

    results = _run_chunked_lens(
        chunks,
        _run_chunk,
        max_workers=options.max_workers,
        event_prefix=event_name,
    )
    _emit_progress(cb, f"{event_name}_done", findings=len(results))
    return results


def run_intra_lens(analyzer, graph, options):
    cb = options.progress_callback
    targets = _structural_candidate_nodes(analyzer, graph)
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
    audit_results = run_reachability_jobs(
        list(groups.items()),
        lambda item: _audit_file(analyzer, item[0], item[1]),
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
    return list(chain.from_iterable(audit_results))


def run_candidate_lens(analyzer, graph, spec, options):
    cb = options.progress_callback
    candidates = _structural_candidate_nodes(
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

    results = _run_chunked_lens(
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
    nodes = _global_lifecycle_nodes(graph, globals_)
    if not nodes:
        return []
    _emit_progress(
        cb,
        Progress.GLOBAL_LIFECYCLE_START,
        globals=len(globals_),
        functions=len(nodes),
    )
    chunks = _build_file_grouped_node_chunks(
        analyzer._cb,
        nodes,
        max_total_chars=SUPPLEMENTARY_GLOBAL_LIFECYCLE_MAX_TOTAL_CHARS,
        per_fn_chars=SUPPLEMENTARY_GLOBAL_LIFECYCLE_PER_FUNCTION_CHARS,
    )
    globals_code = _build_globals_code(graph, max_chars=SUPPLEMENTARY_GLOBALS_MAX_CHARS)

    def _run_chunk(chunk_nodes, code_chunk):
        code = f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{code_chunk}"
        raw = _invoke_combined(analyzer, ["global_lifecycle"], code)
        return _parse_semantic(raw, chunk_nodes, analysis_type="global_lifecycle")

    results = _run_chunked_lens(
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
    for batch in _chunked(conflicts, SUPPLEMENTARY_LOCK_ORDER_BATCH_SIZE):
        nodes, code = _lock_order_batch_context(analyzer, batch)
        raw = _invoke_combined(analyzer, ["lock_order_extraction"], code)
        results.extend(
            _parse_semantic(raw, nodes, analysis_type="lock_order_extraction")
        )
    _emit_progress(cb, Progress.LOCK_ORDER_EXTRACTION_DONE, findings=len(results))
    return results


def _structural_candidate_nodes(analyzer, graph, *, sinks_only=False):
    reverse_edges = _reverse_edges(graph)
    selected = {}

    def add(unique_names, *, with_neighbors=False):
        _add_node_contexts(
            graph,
            reverse_edges,
            selected,
            unique_names,
            with_neighbors=with_neighbors,
        )

    add(
        _source_sink_names(graph.nodes.values(), sinks_only=sinks_only),
        with_neighbors=not sinks_only,
    )

    if not sinks_only:
        add(_global_reference_names(graph, graph.get_globals()), with_neighbors=True)
        add(_connected_node_names(graph, reverse_edges))
        add(_domain_keyword_node_names(analyzer, graph), with_neighbors=True)

    return _sorted_nodes(selected.values())


def _audit_file(analyzer, file_path, functions):
    bodies = [
        f"--- {function.unique_name} (line {function.line_number}) ---\n{body}"
        for function in functions
        if (
            body := _read_function_body(
                analyzer._cb,
                function,
                SUPPLEMENTARY_INTRA_FUNCTION_BODY_CHARS,
            )
        )
    ]
    if not bodies:
        return []
    raw = analyzer._invoke_findings(
        analyzer._with_domain_hints(_INTRA_SYS),
        _INTRA_USR,
        {"file_path": file_path, "functions_code": "\n\n".join(bodies)},
        max_tokens=analyzer._at,
    )
    return _parse_intra(raw, functions)


def _global_lifecycle_nodes(graph, globals_):
    selected = {}
    reverse_edges = _reverse_edges(graph)

    def add(unique_names):
        _add_node_contexts(
            graph,
            reverse_edges,
            selected,
            unique_names,
            with_neighbors=True,
        )

    for global_construct in globals_:
        add(_global_reference_names(graph, [global_construct]))
        add(
            _source_sink_names(
                graph.get_file_nodes(global_construct.file_path),
            )
        )
    return _sorted_nodes(selected.values())


def _lock_order_batch_context(analyzer, batch):
    nodes_by_name = {}
    lines = ["== LOCK ORDER CANDIDATES =="]
    for index, (left, right, node_a, line_a, node_b, line_b) in enumerate(batch):
        lines.append(
            f"Conflict {index}: {left} -> {right} in {node_a.unique_name} line {line_a}; "
            f"{right} -> {left} in {node_b.unique_name} line {line_b}"
        )
        for node in (node_a, node_b):
            nodes_by_name.setdefault(node.unique_name, node)
    nodes = list(nodes_by_name.values())
    body_chunks = _build_file_grouped_chunks(
        analyzer._cb,
        nodes,
        max_total_chars=SUPPLEMENTARY_LOCK_ORDER_MAX_TOTAL_CHARS,
        per_fn_chars=SUPPLEMENTARY_LOCK_ORDER_PER_FUNCTION_CHARS,
    )
    return nodes, (
        "\n".join(lines)
        + "\n\n== RELEVANT FUNCTION BODIES ==\n"
        + "\n\n".join(body_chunks)
    )


def _source_sink_names(nodes, *, sinks_only=False):
    for node in nodes:
        if node.is_sink or (node.is_source and not sinks_only):
            yield node.unique_name


def _global_reference_names(graph, globals_):
    for global_construct in globals_:
        for ref in global_construct.referenced_functions:
            yield from graph.name_index.get(ref, [])


def _connected_node_names(graph, reverse_edges):
    for node in graph.nodes.values():
        degree = len(node.resolved_calls or []) + len(
            reverse_edges.get(node.unique_name, [])
        )
        if degree >= 2:
            yield node.unique_name


def _domain_keyword_node_names(analyzer, graph):
    if not analyzer._domain_keywords:
        return
    for node in graph.nodes.values():
        text = f"{node.name} {' '.join(node.calls or [])}".lower()
        if any(keyword in text for keyword in analyzer._domain_keywords):
            yield node.unique_name


def _add_node_contexts(
    graph, reverse_edges, selected, unique_names, *, with_neighbors=False
):
    for unique_name in unique_names:
        _add_node_context(
            graph,
            reverse_edges,
            selected,
            unique_name,
            with_neighbors=with_neighbors,
        )


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


def _reverse_edges(graph):
    return _build_reverse_edges(graph, lambda item: _node_sort_key(graph, item))


def _sorted_nodes(nodes):
    return sorted(
        nodes,
        key=lambda node: (node.file_path, int(node.line_number or 0), node.name),
    )
