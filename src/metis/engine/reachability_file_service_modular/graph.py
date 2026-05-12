# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

# ruff: noqa: F403,F405

"""Partial graph assembly for a selected single-file review context."""

from __future__ import annotations

from .common import *


class PartialGraphBuilder:
    """Materialize the selected partial context into a small reachability graph."""

    def build(
        self,
        context: PartialReviewContext,
        symbol_index: SymbolIndex,
        codebase_path: str,
    ) -> ReachabilityGraph:
        graph = ReachabilityGraph()
        for node in self._all_nodes(context):
            graph.add_node(node)
        for g in context.globals:
            graph.add_global(g)
        graph.resolve_all_calls()
        return graph

    def candidate_paths(
        self, context: PartialReviewContext, graph: ReachabilityGraph
    ) -> list[ReachabilityPath]:
        paths = list(context.candidate_paths)
        if graph.node_count() <= 260:
            paths.extend(
                PathTracer(
                    graph, max_path_length=8, max_paths_per_source=80
                ).find_all_paths()
            )
        return _dedupe_paths(paths)

    def _all_nodes(self, context: PartialReviewContext) -> list[FunctionNode]:
        nodes = {}
        for group in (
            context.target_nodes,
            context.inbound_callers,
            context.outbound_callees,
            context.shared_state_nodes,
            context.lifecycle_pair_nodes,
            context.callback_nodes,
            context.companion_nodes,
        ):
            for node in group:
                nodes[node.unique_name] = node
        return list(nodes.values())


__all__ = [name for name in globals() if not name.startswith("__")]
