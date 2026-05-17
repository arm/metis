# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Build the full C/C++ reachability graph from tree-sitter extraction."""

from __future__ import annotations

from .c_family_rules import external_sink_type
from .models import ReachabilityGraph
from .c_family import CFamilyTreeSitterExtractor


class TreeSitterReachabilityGraphBuilder:
    """Parse selected C-family files and resolve calls into one graph."""

    def __init__(self):
        self._extractor = CFamilyTreeSitterExtractor()

    def build(
        self, files, codebase_path: str, *, progress_callback=None
    ) -> ReachabilityGraph:
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
                progress_callback(
                    {
                        "event": "treesitter_graph_progress",
                        "completed": completed,
                        "total": total,
                        "file": file_path,
                        "functions": len(parsed.nodes),
                        "globals": len(parsed.globals),
                        "errors": len(parsed.errors),
                        "error_messages": parsed.errors[:3],
                    }
                )

        graph.resolve_all_calls()
        graph.annotate_automatic_sources()
        graph.annotate_external_call_sinks(external_sink_type)
        if progress_callback:
            progress_callback(
                {
                    "event": "treesitter_graph_done",
                    "nodes": graph.node_count(),
                    "edges": graph.edge_count(),
                    "sources": len(graph.get_sources()),
                    "sinks": len(graph.get_sinks()),
                    "globals": len(graph.get_globals()),
                    "errors": errors,
                }
            )
        return graph
