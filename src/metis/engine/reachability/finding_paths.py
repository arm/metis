# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from collections import deque
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import replace
from functools import partial

from metis.reachability_settings import DEFAULT_REACHABILITY_MAX_PATH_LENGTH

from .graph_utils import _node_sort_key
from .graph_utils import _normalize_file_ref


class FindingPathAnnotator:
    def __init__(
        self,
        graph,
        target_file: str,
        *,
        reverse_edges: Mapping[str, Sequence[str]],
        max_path_length: int = DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
    ):
        self._graph = graph
        self._target_file = _normalize_file_ref(target_file)
        self._max_path_length = max(1, int(max_path_length or 1))
        self._node_sort_key = partial(_node_sort_key, self._graph)
        self._reverse_edges = reverse_edges

    def annotate(self, findings):
        return [self.annotate_one(finding) for finding in findings]

    def annotate_one(self, finding):
        target = self._finding_node(finding)
        if not target:
            return finding

        path = self._best_source_path_to(target.unique_name)
        if not path or len(path) <= len(list(getattr(finding, "path", []) or [])):
            return finding

        source = self._graph.get_node(path[0])
        return replace(
            finding,
            source_function=source.unique_name if source else finding.source_function,
            source_file=source.file_path if source else finding.source_file,
            source_line=source.line_number if source else finding.source_line,
            sink_function=target.unique_name,
            sink_file=target.file_path,
            sink_line=target.line_number,
            path=path,
        )

    def _finding_node(self, finding):
        candidates = [
            getattr(finding, "primary_function", ""),
            getattr(finding, "sink_function", ""),
            getattr(finding, "source_function", ""),
        ]
        candidates.extend(reversed(list(getattr(finding, "path", []) or [])))

        primary_file = _normalize_file_ref(getattr(finding, "primary_file", ""))
        wanted_file = primary_file or self._target_file
        if wanted_file and wanted_file != self._target_file:
            return None

        for candidate in candidates:
            node = self._lookup_node(candidate, wanted_file)
            if node and _normalize_file_ref(node.file_path) == self._target_file:
                return node
        return None

    def _lookup_node(self, name: str, wanted_file: str):
        if not name:
            return None
        node = self._graph.get_node(name)
        if node:
            return node

        short_name = str(name).split("::")[-1]
        matches = [
            node
            for unique in self._graph.name_index.get(short_name, ())
            if (node := self._graph.get_node(unique)) is not None
        ]
        if wanted_file:
            same_file = [
                node
                for node in matches
                if _normalize_file_ref(node.file_path) == wanted_file
            ]
            if same_file:
                matches = same_file
        return min(matches, key=self._node_sort_key) if matches else None

    def _best_source_path_to(self, target_name: str) -> list[str]:
        target = self._graph.get_node(target_name)
        if not target:
            return []
        if target.is_source:
            return [target_name]

        queue = deque([target_name])
        parents: dict[str, str | None] = {target_name: None}
        depths = {target_name: 1}
        while queue:
            current_name = queue.popleft()
            depth = depths[current_name]
            if depth >= self._max_path_length:
                continue
            for caller_name in self._reverse_edges.get(current_name, ()):
                if caller_name in parents:
                    continue
                caller = self._graph.get_node(caller_name)
                if not caller:
                    continue
                parents[caller_name] = current_name
                depths[caller_name] = depth + 1
                if caller.is_source:
                    path = [caller_name]
                    parent = parents[caller_name]
                    while parent is not None:
                        path.append(parent)
                        parent = parents[parent]
                    return path
                queue.append(caller_name)
        return []
