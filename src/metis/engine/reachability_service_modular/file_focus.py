# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Reviewed-file focus selection for full-graph ``review_file`` runs."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from functools import partial

from ..reachability_common.models import ReachabilityPath
from ..reachability_common.graph_utils import (
    _build_reverse_edges,
    _file_focus_path_sort_key,
    _node_sort_key,
)


DEFAULT_MAX_SOURCE_TO_FILE_PATHS = 64
DEFAULT_MAX_SOURCE_PATHS_PER_TARGET = 10
DEFAULT_MAX_SOURCE_PATH_VARIANTS = 2
DEFAULT_MAX_OUTGOING_CONTEXT_PATHS = 24
DEFAULT_MAX_OUTGOING_PATHS_PER_TARGET = 4


@dataclass
class FileFocus:
    """Bounded graph slice centered on one target file."""

    target_file: str
    target_nodes: list[str] = field(default_factory=list)
    incoming_paths: list[ReachabilityPath] = field(default_factory=list)
    outgoing_context_paths: list[ReachabilityPath] = field(default_factory=list)
    node_names: set[str] = field(default_factory=set)


class FileFocusBuilder:
    """Build reviewed-file-centered context from the deterministic call graph.

    The primary paths are source -> reviewed-file-function paths. Sink reachability
    is deliberately secondary and only contributes capped downstream context.
    """

    def __init__(
        self,
        graph,
        *,
        max_path_length: int = 25,
        max_incoming_paths: int | None = DEFAULT_MAX_SOURCE_TO_FILE_PATHS,
        max_incoming_paths_per_target: int = DEFAULT_MAX_SOURCE_PATHS_PER_TARGET,
        max_path_variants_per_source_target: int = DEFAULT_MAX_SOURCE_PATH_VARIANTS,
        max_outgoing_context_paths: int = DEFAULT_MAX_OUTGOING_CONTEXT_PATHS,
        max_outgoing_paths_per_target: int = DEFAULT_MAX_OUTGOING_PATHS_PER_TARGET,
    ):
        self._graph = graph
        self._max_path_length = max(1, int(max_path_length or 1))
        if max_incoming_paths is None:
            max_incoming_paths = DEFAULT_MAX_SOURCE_TO_FILE_PATHS
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
        paths: list[ReachabilityPath] = []
        target_name = target_node.unique_name
        if target_node.is_source:
            paths.append(
                ReachabilityPath(
                    source=target_name,
                    sink=target_name,
                    path=[target_name],
                    sink_type=target_node.sink_type or "target_file_function",
                )
            )

        queue = deque([[target_name]])
        while queue and len(paths) < self._max_incoming_paths_per_target:
            reverse_path = queue.popleft()
            upstream = reverse_path[-1]
            if len(reverse_path) >= self._max_path_length:
                continue
            for caller_name in self._reverse_edges.get(upstream, []):
                if caller_name in reverse_path:
                    continue
                caller = self._graph.get_node(caller_name)
                if not caller:
                    continue
                next_reverse_path = reverse_path + [caller_name]
                if caller.is_source:
                    forward_path = list(reversed(next_reverse_path))
                    paths.append(
                        ReachabilityPath(
                            source=caller_name,
                            sink=target_name,
                            path=forward_path,
                            sink_type=target_node.sink_type or "target_file_function",
                        )
                    )
                    if len(paths) >= self._max_incoming_paths_per_target:
                        break
                queue.append(next_reverse_path)

        return self._dedupe_and_rank_paths(
            paths,
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
        paths: list[ReachabilityPath] = []
        target_name = target_node.unique_name
        if target_node.is_sink:
            paths.append(
                ReachabilityPath(
                    source=target_name,
                    sink=target_name,
                    path=[target_name],
                    sink_type=target_node.sink_type,
                )
            )

        queue = deque([[target_name]])
        while queue and len(paths) < self._max_outgoing_paths_per_target:
            path = queue.popleft()
            current_name = path[-1]
            current = self._graph.get_node(current_name)
            if not current or len(path) >= self._max_path_length:
                continue
            for callee_name in sorted(
                current.resolved_calls or [], key=self._node_sort_key
            ):
                if callee_name in path:
                    continue
                callee = self._graph.get_node(callee_name)
                if not callee:
                    continue
                next_path = path + [callee_name]
                if callee.is_sink:
                    paths.append(
                        ReachabilityPath(
                            source=target_name,
                            sink=callee_name,
                            path=next_path,
                            sink_type=callee.sink_type,
                        )
                    )
                    if len(paths) >= self._max_outgoing_paths_per_target:
                        break
                queue.append(next_path)

        return self._dedupe_and_rank_paths(
            paths,
            max_total=self._max_outgoing_paths_per_target,
        )

    def _focus_node_names(
        self, target_nodes, incoming_paths, outgoing_paths
    ) -> set[str]:
        needed = {node.unique_name for node in target_nodes}
        for path in list(incoming_paths or []) + list(outgoing_paths or []):
            needed.update(path.path or [])

        # Keep a direct local neighborhood even when source reachability is sparse.
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
