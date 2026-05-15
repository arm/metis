# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Source-path enrichment for findings that start at a primary function."""

from __future__ import annotations

from collections import deque
from dataclasses import replace

from ..reachability_common.graph_utils import _build_reverse_edges


class FindingPathAnnotator:
    """Attach deterministic source-to-defect paths to file-review findings.

    Supplementary audit passes often identify the defective function directly and
    emit a single-node path. This helper keeps that finding but enriches it with
    the best source-to-primary-function path from the full tree-sitter graph.
    """

    def __init__(self, graph, target_file: str, *, max_path_length: int = 25):
        self._graph = graph
        self._target_file = self._norm_file(target_file)
        self._max_path_length = max(1, int(max_path_length or 1))
        self._reverse_edges = _build_reverse_edges(
            self._graph, self._node_name_sort_key
        )

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

        primary_file = self._norm_file(getattr(finding, "primary_file", ""))
        wanted_file = primary_file or self._target_file
        if wanted_file and wanted_file != self._target_file:
            return None

        for candidate in candidates:
            node = self._lookup_node(candidate, wanted_file)
            if node and self._norm_file(node.file_path) == self._target_file:
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
            self._graph.get_node(unique)
            for unique in self._graph.name_index.get(short_name, [])
        ]
        matches = [node for node in matches if node is not None]
        if wanted_file:
            same_file = [
                node
                for node in matches
                if self._norm_file(node.file_path) == wanted_file
            ]
            if same_file:
                return sorted(same_file, key=self._node_sort_key)[0]
        return sorted(matches, key=self._node_sort_key)[0] if matches else None

    def _best_source_path_to(self, target_name: str) -> list[str]:
        target = self._graph.get_node(target_name)
        if not target:
            return []
        if target.is_source:
            return [target_name]

        queue = deque([[target_name]])
        while queue:
            reverse_path = queue.popleft()
            if len(reverse_path) >= self._max_path_length:
                continue
            upstream = reverse_path[-1]
            for caller_name in self._reverse_edges.get(upstream, []):
                if caller_name in reverse_path:
                    continue
                caller = self._graph.get_node(caller_name)
                if not caller:
                    continue
                next_reverse_path = reverse_path + [caller_name]
                if caller.is_source:
                    return list(reversed(next_reverse_path))
                queue.append(next_reverse_path)
        return []

    def _node_name_sort_key(self, node_name: str):
        node = self._graph.get_node(node_name)
        return self._node_sort_key(node) if node else ("", 0, "", node_name)

    def _node_sort_key(self, node):
        return (
            self._norm_file(node.file_path),
            int(node.line_number or 0),
            node.name,
            node.unique_name,
        )

    def _norm_file(self, value: str) -> str:
        return str(value or "").replace("\\", "/")
