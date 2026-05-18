# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Small graph and sequence helpers for reachability analysis."""
from __future__ import annotations

from collections import defaultdict
import hashlib

from metis.reachability_settings import DEFAULT_REACHABILITY_MAX_PATHS

from .models import FunctionNode, ReachabilityGraph

_AUTO_CONFIRMATION_MAX_PATHS = 48
_AUTO_CONFIRMATION_MAX_ENDPOINTS = 12
_AUTO_CONFIRMATION_PATHS_PER_ENDPOINT = 4


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


def graph_fingerprint(graph) -> str:
    """Return a deterministic identity for graph content that affects analysis."""
    digest = hashlib.sha256()

    def update(*parts) -> None:
        digest.update("\x1f".join(str(part or "") for part in parts).encode("utf-8"))
        digest.update(b"\n")

    for node in sorted(graph.nodes.values(), key=lambda item: item.unique_name):
        update(
            "node",
            node.unique_name,
            node.file_path,
            node.name,
            node.line_number,
            node.language,
            int(bool(node.is_source)),
            int(bool(node.is_sink)),
            node.source_reason,
            node.sink_type,
            node.sink_reason,
            ",".join(node.calls or ()),
            ",".join(node.resolved_calls or ()),
        )
    for construct in sorted(graph.get_globals(), key=lambda item: item.unique_name):
        update(
            "global",
            construct.unique_name,
            construct.file_path,
            construct.name,
            construct.line_number,
            construct.initializer,
            ",".join(construct.referenced_functions or ()),
        )
    return digest.hexdigest()


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
                language=node.language,
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


def select_confirmation_paths(
    paths, graph, *, max_paths=DEFAULT_REACHABILITY_MAX_PATHS
):
    """Pick a bounded, representative set of source-rooted paths for LLM review."""
    paths = _dedupe_paths(paths)
    if max_paths and int(max_paths) > 0:
        return paths[: int(max_paths)]
    if len(paths) <= _AUTO_CONFIRMATION_MAX_PATHS:
        return paths

    indexed = list(enumerate(paths))
    indexed.sort(key=lambda item: _confirmation_path_rank(item[1], graph))
    selected = []
    endpoint_counts = {}
    for original_index, path in indexed:
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
        selected.append((original_index, path))
        if len(selected) >= _AUTO_CONFIRMATION_MAX_PATHS:
            break

    selected.sort(key=lambda item: item[0])
    return [path for _original_index, path in selected]


def _confirmation_path_rank(path, graph):
    node_names = list(path.path or [])
    nodes = [graph.get_node(name) for name in node_names]
    nodes = [node for node in nodes if node is not None]
    endpoint = graph.get_node(path.sink)
    sink_count = sum(1 for node in nodes if node.is_sink)
    source = graph.get_node(path.source)
    return (
        -sink_count,
        -int(bool(endpoint and endpoint.is_sink)),
        -int(bool(endpoint and endpoint.sink_type and endpoint.sink_type != "other")),
        len(node_names),
        endpoint.file_path if endpoint else "",
        int(endpoint.line_number or 0) if endpoint else 0,
        source.file_path if source else "",
        int(source.line_number or 0) if source else 0,
        tuple(node_names),
    )
