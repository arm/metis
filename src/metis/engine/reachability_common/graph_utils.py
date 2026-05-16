# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Small graph and sequence helpers for reachability analysis."""
from __future__ import annotations

from collections import defaultdict

from .models import FunctionNode, ReachabilityGraph


def _chunked(items, size):
    if size <= 0:
        size = 1
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _dedupe_paths(paths):
    seen, results = set(), []
    for p in paths:
        key = (p.source, p.sink, tuple(p.path))
        if key not in seen:
            seen.add(key)
            results.append(p)
    return results


def _build_reverse_edges(graph, sort_key):
    reverse = defaultdict(list)
    for node in graph.nodes.values():
        for callee in node.resolved_calls or []:
            reverse[callee].append(node.unique_name)
    for callers in reverse.values():
        callers.sort(key=sort_key)
    return dict(reverse)


def _normalize_file_ref(value):
    return str(value or "").replace("\\", "/")


def _same_file(a, b):
    return _normalize_file_ref(a) == _normalize_file_ref(b)


def _node_sort_key(graph, node_or_name):
    node = (
        graph.get_node(node_or_name) if isinstance(node_or_name, str) else node_or_name
    )
    if not node:
        return ("", 0, str(node_or_name or ""))
    return (
        _normalize_file_ref(node.file_path),
        int(node.line_number or 0),
        node.name,
        node.unique_name,
    )


def _source_rooted_path_sort_key(graph, path):
    endpoint = graph.get_node(path.sink)
    source = graph.get_node(path.source)
    return (
        source.file_path if source else "",
        int(source.line_number or 0) if source else 0,
        source.name if source else path.source,
        len(path.path or []),
        endpoint.file_path if endpoint else "",
        int(endpoint.line_number or 0) if endpoint else 0,
        endpoint.name if endpoint else path.sink,
        tuple(path.path or []),
    )


def _file_focus_path_sort_key(graph, path):
    target = graph.get_node(path.sink)
    source = graph.get_node(path.source)
    return (
        len(path.path or []),
        target.file_path if target else "",
        int(target.line_number or 0) if target else 0,
        target.name if target else path.sink,
        source.file_path if source else "",
        int(source.line_number or 0) if source else 0,
        source.name if source else path.source,
        tuple(path.path or []),
    )


def _copy_graph_nodes(graph, node_names):
    focus = ReachabilityGraph()
    for unique_name in sorted(node_names):
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
