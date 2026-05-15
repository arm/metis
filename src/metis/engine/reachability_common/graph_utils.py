# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Small graph and sequence helpers for reachability analysis."""
from __future__ import annotations


from collections import defaultdict


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
