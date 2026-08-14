# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from collections import deque
from dataclasses import dataclass
from dataclasses import field
from functools import partial

from metis.engine.codegraph import CodeGraph
from metis.engine.nodes.reachability.options import DEFAULT_REACHABILITY_MAX_PATH_LENGTH

from .domain import ReachabilityPath
from .graph_utils import _build_reverse_edges
from .graph_utils import _node_sort_key
from .graph_utils import _select_diverse_paths


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

        incoming, incoming_nodes = self._source_to_target_paths(target_nodes)
        outgoing, outgoing_nodes = self._outgoing_context_paths(target_nodes)
        focus.node_names = self._focus_node_names(target_nodes, incoming, outgoing)
        focus.node_names.update(incoming_nodes)
        focus.node_names.update(outgoing_nodes)
        return focus

    def _source_to_target_paths(
        self,
        target_nodes,
    ) -> tuple[list[ReachabilityPath], set[str]]:
        paths, reached = self._paths_and_nodes_for_targets(target_nodes, reverse=True)
        return (
            _select_diverse_paths(
                paths,
                self._graph,
                group_by="sink",
                max_paths=0,
            ),
            reached,
        )

    def _outgoing_context_paths(
        self,
        target_nodes,
    ) -> tuple[list[ReachabilityPath], set[str]]:
        paths, reached = self._paths_and_nodes_for_targets(target_nodes, reverse=False)
        return (
            _select_diverse_paths(
                paths,
                self._graph,
                group_by="source",
                max_paths=0,
            ),
            reached,
        )

    def _paths_and_nodes_for_targets(
        self,
        target_nodes,
        *,
        reverse: bool,
    ) -> tuple[list[ReachabilityPath], set[str]]:
        paths: list[ReachabilityPath] = []
        reached: set[str] = set()
        for target in target_nodes:
            target_paths, target_reached = self._paths_for_target(
                target,
                reverse=reverse,
            )
            paths.extend(target_paths)
            reached.update(target_reached)
        return paths, reached

    def _paths_for_target(
        self, target_node, *, reverse: bool
    ) -> tuple[list[ReachabilityPath], set[str]]:
        target_name = target_node.unique_name
        distances = {target_name: 0}
        parents: dict[str, str | None] = {target_name: None}
        queue = deque([target_name])
        while queue:
            current_name = queue.popleft()
            current = self._graph.get_node(current_name)
            distance = distances[current_name]
            if current is None:
                continue
            next_names = (
                self._reverse_edges.get(current_name, [])
                if reverse
                else sorted(current.resolved_calls or [], key=self._node_sort_key)
            )
            for next_name in next_names:
                if self._graph.get_node(next_name) is None:
                    continue
                next_distance = distance + 1
                known_distance = distances.get(next_name)
                if known_distance is None:
                    distances[next_name] = next_distance
                    parents[next_name] = current_name
                    queue.append(next_name)
                elif known_distance == next_distance:
                    selected_parent = parents[next_name]
                    if selected_parent is None or self._node_sort_key(
                        current_name
                    ) < self._node_sort_key(selected_parent):
                        parents[next_name] = current_name

        boundary_names = [
            name
            for name in distances
            if (
                (node := self._graph.get_node(name)) is not None
                and (node.is_source if reverse else node.is_sink)
            )
        ]
        paths: list[ReachabilityPath] = []
        for boundary_name in sorted(boundary_names, key=self._node_sort_key):
            boundary_node = self._graph.get_node(boundary_name)
            if boundary_node is None:
                continue
            route = self._shortest_route(
                boundary_name,
                target_name,
                parents,
            )
            if len(route) > self._max_path_length:
                continue
            forward_path = route if reverse else list(reversed(route))
            paths.append(
                ReachabilityPath(
                    boundary_name if reverse else target_name,
                    target_name if reverse else boundary_name,
                    forward_path,
                    (
                        target_node.sink_type or "target_file_function"
                        if reverse
                        else boundary_node.sink_type
                    ),
                )
            )
        return paths, set(distances)

    def _shortest_route(
        self,
        boundary_name: str,
        target_name: str,
        parents: dict[str, str | None],
    ) -> list[str]:
        route = [boundary_name]
        current_name = boundary_name
        while current_name != target_name:
            parent = parents[current_name]
            if parent is None:
                raise RuntimeError("shortest-path predecessor chain is incomplete")
            current_name = parent
            route.append(current_name)
        return route

    def _focus_node_names(
        self, target_nodes, incoming_paths, outgoing_paths
    ) -> set[str]:
        needed = {node.unique_name for node in target_nodes}
        for path in list(incoming_paths or []) + list(outgoing_paths or []):
            needed.update(path.path or [])

        for node in target_nodes:
            needed.update(node.resolved_calls or [])
            for caller_name in self._reverse_edges.get(node.unique_name, []):
                needed.add(caller_name)
        return needed
