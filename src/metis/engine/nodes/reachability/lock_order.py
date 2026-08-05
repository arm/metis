# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections import defaultdict

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import FunctionNode

from .limits import LOCK_ORDER_MAX_CONFLICTS

type LockConflict = tuple[str, str, FunctionNode, int, FunctionNode, int]


def _extract_lock_conflicts(graph: CodeGraph) -> list[LockConflict]:
    edges: dict[
        tuple[str, str],
        list[tuple[FunctionNode, int]],
    ] = defaultdict(list)
    for node in graph.nodes.values():
        _record_lock_edges(edges, node)

    conflicts: list[LockConflict] = []
    seen: set[tuple[str, ...]] = set()
    for (first_lock, second_lock), first_edges in edges.items():
        reverse_edges = edges.get((second_lock, first_lock))
        if not reverse_edges:
            continue
        for first_node, first_line in first_edges:
            for second_node, second_line in reverse_edges:
                if first_node.unique_name == second_node.unique_name:
                    continue
                key = tuple(
                    sorted((first_node.unique_name, second_node.unique_name))
                    + sorted((first_lock, second_lock))
                )
                if key in seen:
                    continue
                seen.add(key)
                conflicts.append(
                    (
                        first_lock,
                        second_lock,
                        first_node,
                        first_line,
                        second_node,
                        second_line,
                    )
                )
                if len(conflicts) >= LOCK_ORDER_MAX_CONFLICTS:
                    return conflicts
    return conflicts


def _record_lock_edges(
    edges: dict[tuple[str, str], list[tuple[FunctionNode, int]]],
    node: FunctionNode,
) -> None:
    held: list[str] = []
    for event in node.lock_events:
        if event.operation == "release":
            if event.lock in held:
                held.remove(event.lock)
            continue
        for prior in held:
            if prior != event.lock:
                edges[(prior, event.lock)].append((node, event.line))
        if event.lock not in held:
            held.append(event.lock)
