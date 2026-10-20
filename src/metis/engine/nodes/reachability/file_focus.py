# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from collections import deque
from collections.abc import Collection
from dataclasses import dataclass
from dataclasses import field

from metis.engine.codegraph import CodeGraph
from metis.engine.nodes.reachability.options import DEFAULT_REACHABILITY_MAX_PATH_LENGTH

from .graph_utils import _build_reverse_edges


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
        self._reverse_edges = _build_reverse_edges(self._graph, None)

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

        focus.node_names = self.node_names_for_targets(focus.target_nodes)
        return focus

    def node_names_for_targets(self, target_names: Collection[str]) -> set[str]:
        node_names: set[str] = set()
        for reverse in (True, False):
            reached = set(target_names)
            queue = deque(target_names)
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
            node_names.update(reached)

        for target_name in target_names:
            node = self._graph.get_node(target_name)
            if node is not None:
                node_names.update(node.resolved_calls or [])
            node_names.update(self._reverse_edges.get(target_name, []))
        return node_names
