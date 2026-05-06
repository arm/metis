# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os

from ..reachability_service import ReachabilityGraph
from .c_family import CFamilyTreeSitterExtractor


class TreeSitterReachabilityGraphBuilder:
    def __init__(self):
        self._extractor = CFamilyTreeSitterExtractor()

    def build(self, files, codebase_path: str, *, progress_callback=None) -> ReachabilityGraph:
        graph = ReachabilityGraph()
        files = sorted(str(file) for file in files)
        total = len(files)
        errors: list[str] = []
        if progress_callback:
            progress_callback({"event": "treesitter_graph_start", "total": total})

        for completed, file_path in enumerate(files, start=1):
            parsed = self._extractor.parse_file(
                codebase_path=codebase_path,
                file_path=file_path,
            )
            errors.extend(parsed.errors)
            for node in parsed.nodes:
                graph.add_node(node)
            for global_construct in parsed.globals:
                graph.add_global(global_construct)
            if progress_callback:
                progress_callback({
                    "event": "treesitter_graph_progress",
                    "completed": completed,
                    "total": total,
                    "file": file_path,
                    "functions": len(parsed.nodes),
                    "globals": len(parsed.globals),
                    "errors": len(parsed.errors),
                    "error_messages": parsed.errors[:3],
                })

        graph.resolve_all_calls()
        if progress_callback:
            progress_callback({
                "event": "treesitter_graph_done",
                "nodes": graph.node_count(),
                "edges": graph.edge_count(),
                "sources": len(graph.get_sources()),
                "sinks": len(graph.get_sinks()),
                "globals": len(graph.get_globals()),
                "errors": errors,
            })
        return graph


def c_cpp_files(files) -> list[str]:
    allowed = {".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".hxx", ".cxx"}
    return [
        str(path)
        for path in files
        if os.path.splitext(str(path))[1].lower() in allowed
    ]
