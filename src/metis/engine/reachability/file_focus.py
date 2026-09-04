# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from collections import defaultdict, deque
from dataclasses import dataclass, field
from functools import partial

from metis.reachability_settings import DEFAULT_REACHABILITY_MAX_PATH_LENGTH

from .graph_utils import (
    _build_reverse_edges,
    _file_focus_path_sort_key,
    _node_sort_key,
)
from .limits import (
    FILE_FOCUS_MAX_OUTGOING_CONTEXT_PATHS,
    FILE_FOCUS_MAX_OUTGOING_PATHS_PER_TARGET,
    FILE_FOCUS_MAX_SOURCE_PATH_VARIANTS,
    FILE_FOCUS_MAX_SOURCE_PATHS_PER_TARGET,
    FILE_FOCUS_MAX_SOURCE_TO_FILE_PATHS,
)
from .domain import ReachabilityPath


@dataclass
class FileFocus:
    target_file: str
    target_nodes: list[str] = field(default_factory=list)
    incoming_paths: list[ReachabilityPath] = field(default_factory=list)
    outgoing_context_paths: list[ReachabilityPath] = field(default_factory=list)
    node_names: set[str] = field(default_factory=set)


class FileFocusBuilder:
    def __init__(
        self,
        graph,
        *,
        max_path_length: int = DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
        max_incoming_paths: int | None = FILE_FOCUS_MAX_SOURCE_TO_FILE_PATHS,
        max_incoming_paths_per_target: int = FILE_FOCUS_MAX_SOURCE_PATHS_PER_TARGET,
        max_path_variants_per_source_target: int = FILE_FOCUS_MAX_SOURCE_PATH_VARIANTS,
        max_outgoing_context_paths: int = FILE_FOCUS_MAX_OUTGOING_CONTEXT_PATHS,
        max_outgoing_paths_per_target: int = FILE_FOCUS_MAX_OUTGOING_PATHS_PER_TARGET,
    ):
        self._graph = graph
        self._max_path_length = max(1, int(max_path_length or 1))
        if max_incoming_paths is None:
            max_incoming_paths = FILE_FOCUS_MAX_SOURCE_TO_FILE_PATHS
        self._max_incoming_paths = max(0, int(max_incoming_paths or 0))
        self._max_incoming_paths_per_target = max(
            1, int(max_incoming_paths_per_target or 1)
        )
        self._max_path_variants = max(1, int(max_path_variants_per_source_target or 1))
        self._max_outgoing_paths = max(0, int(max_outgoing_context_paths or 0))
        self._max_outgoing_paths_per_target = max(
            1, int(max_outgoing_paths_per_target or 1)
        )
        self._node_sort_key = partial(_node_sort_key, self._graph)
        self._path_sort_key = partial(_file_focus_path_sort_key, self._graph)
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

        incoming = self._source_to_target_paths(target_nodes)
        outgoing = self._outgoing_context_paths(target_nodes)
        focus.incoming_paths = incoming
        focus.outgoing_context_paths = outgoing
        focus.node_names = self._focus_node_names(target_nodes, incoming, outgoing)
        return focus

    def _source_to_target_paths(self, target_nodes) -> list[ReachabilityPath]:
        selected: list[ReachabilityPath] = []
        for target in target_nodes:
            if self._max_incoming_paths and len(selected) >= self._max_incoming_paths:
                break
            target_paths = self._incoming_paths_for_target(target)
            remaining = (
                self._max_incoming_paths - len(selected)
                if self._max_incoming_paths
                else len(target_paths)
            )
            selected.extend(target_paths[:remaining])
        return self._dedupe_and_rank_paths(selected, max_total=self._max_incoming_paths)

    def _incoming_paths_for_target(self, target_node) -> list[ReachabilityPath]:
        return self._dedupe_and_rank_paths(
            self._paths_for_target(
                target_node,
                reverse=True,
            ),
            max_total=self._max_incoming_paths_per_target,
        )

    def _outgoing_context_paths(self, target_nodes) -> list[ReachabilityPath]:
        if self._max_outgoing_paths <= 0:
            return []
        paths: list[ReachabilityPath] = []
        for target in target_nodes:
            if len(paths) >= self._max_outgoing_paths:
                break
            target_paths = self._outgoing_paths_for_target(target)
            remaining = self._max_outgoing_paths - len(paths)
            paths.extend(target_paths[:remaining])
        return self._dedupe_and_rank_paths(paths, max_total=self._max_outgoing_paths)

    def _outgoing_paths_for_target(self, target_node) -> list[ReachabilityPath]:
        return self._dedupe_and_rank_paths(
            self._paths_for_target(
                target_node,
                reverse=False,
            ),
            max_total=self._max_outgoing_paths_per_target,
        )

    def _paths_for_target(
        self, target_node, *, reverse: bool
    ) -> list[ReachabilityPath]:
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
            route = self._shortest_route(boundary_name, target_name, parents)
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
        return paths

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

    def _dedupe_and_rank_paths(
        self, paths, *, max_total: int
    ) -> list[ReachabilityPath]:
        exact_seen = set()
        grouped: dict[tuple[str, str], list[ReachabilityPath]] = defaultdict(list)
        for path in paths:
            if not path.path:
                continue
            key = (path.source, path.sink, tuple(path.path))
            if key in exact_seen:
                continue
            exact_seen.add(key)
            grouped[(path.source, path.sink)].append(path)

        selected = []
        for group in grouped.values():
            ranked = sorted(group, key=self._path_sort_key)
            selected.extend(ranked[: self._max_path_variants])

        selected = sorted(selected, key=self._path_sort_key)
        if max_total > 0:
            selected = selected[:max_total]
        return selected
