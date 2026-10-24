# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections import defaultdict
from collections.abc import Sequence

from .models import CodeGraph
from .models import FunctionNode


def _build_reverse_edges(graph, sort_key):
    reverse = defaultdict(list)
    for node in graph.nodes.values():
        for callee in node.resolved_calls or []:
            reverse[callee].append(node.unique_name)
    if sort_key is not None:
        for callers in reverse.values():
            callers.sort(key=sort_key)
    return dict(reverse)


def function_for_location(
    graph: CodeGraph,
    file_path: str,
    line: int,
    *,
    symbol: str = "",
    nodes: Sequence[FunctionNode] | None = None,
) -> FunctionNode | None:
    if nodes is None:
        nodes = graph.get_file_nodes(file_path)
    if not nodes:
        return None
    line = max(1, int(line or 1))
    containing = [
        node
        for node in nodes
        if int(node.line_number or 0)
        <= line
        <= int(node.end_line or node.line_number or 0)
    ]
    if not containing:
        return None
    if symbol:
        exact = [
            node
            for node in containing
            if symbol in {node.unique_name, node.name}
            or node.unique_name.endswith(f"::{symbol}")
        ]
        if exact:
            containing = exact
    return max(containing, key=lambda node: int(node.line_number or 0))
