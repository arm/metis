# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from collections import deque
from dataclasses import dataclass
from dataclasses import field
from functools import partial

from metis.engine.codegraph import CodeGraph
from metis.engine.nodes.reachability.options import DEFAULT_REACHABILITY_MAX_PATH_LENGTH

from .graph_utils import _build_reverse_edges
from .graph_utils import _node_sort_key


@dataclass
class FileFocus:
    target_file: str
    target_nodes: list[str] = field(default_factory=list)
    node_names: set[str] = field(default_factory=set)


class FileFocusBuilder:
    def __init__(
        self,
        graph: CodeGraph,
        *,
        max_path_length: int = DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
    ):
        self._graph = graph
        self._max_path_length = max(1, int(max_path_length or 1))
        self._node_sort_key = partial(_node_sort_key, self._graph)
        self._reverse_edges = _build_reverse_edges(self._graph, self._node_sort_key)

    def build(self, target_file: str) -> FileFocus:
        target_nodes = sorted(
            self._graph.get_file_nodes(target_file),
            key=lambda node: (int(node.line_number or 0), node.name, node.unique_name),
        )
        focus = FileFocus(
            target_file=target_file,
            target_nodes=[node.unique_name for node in target_nodes],
        )
        if not target_nodes:
            return focus

        for reverse in (True, False):
            reached = set(focus.target_nodes)
            queue = deque(focus.target_nodes)
            while queue:
                current_name = queue.popleft()
                current = self._graph.get_node(current_name)
                if current is None:
                    continue
                next_names = (
                    self._reverse_edges.get(current_name, [])
                    if reverse
                    else current.resolved_calls or []
                )
                for next_name in next_names:
                    if next_name in reached or self._graph.get_node(next_name) is None:
                        continue
                    reached.add(next_name)
                    queue.append(next_name)
            focus.node_names.update(reached)

        for node in target_nodes:
            focus.node_names.update(node.resolved_calls or [])
            focus.node_names.update(self._reverse_edges.get(node.unique_name, []))
        return focus
