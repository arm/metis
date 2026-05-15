# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Path tracing utilities over the shared reachability graph."""

from __future__ import annotations
from collections import defaultdict

from .models import ReachabilityPath
from .graph_utils import _dedupe_paths


class SourceRootedPathTracer:
    """Trace maximal source-rooted paths without relying on sink labels."""

    def __init__(self, graph, *, max_path_length=25, max_paths_per_source=200):
        self._g = graph
        self._ml = max(1, int(max_path_length or 1))
        self._mp = max(1, int(max_paths_per_source or 1))

    def find_all_paths(self):
        sources = sorted(self._g.get_sources(), key=self._node_sort_key)
        if not sources:
            return []
        paths = []
        for source in sources:
            paths.extend(self._terminal_paths_from_source(source.unique_name))
        return self._drop_strict_prefix_paths(_dedupe_paths(paths))

    def _terminal_paths_from_source(self, source_name):
        results, stack = [], [[source_name]]
        while stack and len(results) < self._mp:
            path = stack.pop()
            node = self._g.get_node(path[-1])
            if not node:
                continue
            callees = [
                callee
                for callee in sorted(node.resolved_calls or [], key=self._node_sort_key)
                if callee not in path
            ]
            if not callees or len(path) >= self._ml:
                results.append(self._to_path(source_name, path))
                continue
            for callee in reversed(callees):
                stack.append(path + [callee])
        return results

    def _to_path(self, source_name, path):
        endpoint_name = path[-1]
        endpoint = self._g.get_node(endpoint_name)
        return ReachabilityPath(
            source=source_name,
            sink=endpoint_name,
            path=list(path),
            sink_type=(
                endpoint.sink_type
                if endpoint and endpoint.is_sink
                else "reachable_endpoint"
            ),
        )

    def _drop_strict_prefix_paths(self, paths):
        by_source = defaultdict(list)
        for path in paths:
            by_source[path.source].append(path)

        selected = []
        for group in by_source.values():
            tuples = [(path, tuple(path.path or [])) for path in group if path.path]
            for path, path_tuple in tuples:
                if any(
                    len(other_tuple) > len(path_tuple)
                    and other_tuple[: len(path_tuple)] == path_tuple
                    for _other, other_tuple in tuples
                ):
                    continue
                selected.append(path)
        return sorted(selected, key=self._path_sort_key)

    def _node_sort_key(self, node_or_name):
        node = node_or_name
        if isinstance(node_or_name, str):
            node = self._g.get_node(node_or_name)
        if not node:
            return ("", 0, str(node_or_name))
        return (node.file_path, int(node.line_number or 0), node.name, node.unique_name)

    def _path_sort_key(self, path):
        endpoint = self._g.get_node(path.sink)
        source = self._g.get_node(path.source)
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
