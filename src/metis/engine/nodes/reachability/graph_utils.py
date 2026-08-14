# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import replace
import hashlib
from typing import Literal

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import FunctionNode
from .domain import ReachabilityPath


def _dedupe_paths(paths):
    seen, results = set(), []
    for p in paths:
        key = (p.source, p.sink, tuple(p.path))
        if key not in seen:
            seen.add(key)
            results.append(p)
    return results


def _build_reverse_edges(graph, sort_key):
    reverse = defaultdict(list)
    for node in graph.nodes.values():
        for callee in node.resolved_calls or []:
            reverse[callee].append(node.unique_name)
    for callers in reverse.values():
        callers.sort(key=sort_key)
    return dict(reverse)


def graph_fingerprint(graph) -> str:
    digest = hashlib.sha256()

    def update(*parts) -> None:
        digest.update("\x1f".join(str(part or "") for part in parts).encode("utf-8"))
        digest.update(b"\n")

    for node in sorted(graph.nodes.values(), key=lambda item: item.unique_name):
        update(
            "node",
            node.unique_name,
            node.file_path,
            node.name,
            node.line_number,
            node.language,
            node.parameter_count,
            node.end_line,
            node.start_byte,
            node.end_byte,
            int(node.is_public_entrypoint),
            node.entrypoint_reason,
            int(node.has_internal_linkage),
            int(node.is_source),
            int(node.is_sink),
            node.source_reason,
            node.sink_type,
            node.sink_reason,
            ",".join(node.calls or ()),
            ",".join(node.resolved_calls or ()),
        )
        for call in node.call_sites:
            update(
                "call_site",
                node.unique_name,
                call.symbol,
                call.line,
                call.argument_count,
                call.kind,
                call.start_byte,
                call.end_byte,
                call.qualified_name,
                call.generic_qualified_name,
                call.receiver,
                repr(call.target_ids),
                int(call.targets_complete),
                repr(call.arguments),
                repr(call.conditions),
                repr(call.must_conditions),
                repr(call.result),
            )
        for assignment in node.assignments:
            update("assignment", node.unique_name, repr(assignment))
        for loop in node.loops:
            update("loop", node.unique_name, repr(loop))
        for return_site in node.returns:
            update("return", node.unique_name, repr(return_site))
        update(
            "parameters",
            node.unique_name,
            repr(node.parameters),
        )
        for key, tag in sorted(node.tags.items()):
            update("tag", node.unique_name, key, tag.value, tag.reason)
        for reference in node.references:
            update(
                "reference",
                node.unique_name,
                reference.symbol,
                reference.line,
                reference.start_byte,
                reference.end_byte,
                repr(reference.target_ids),
            )
    for construct in sorted(graph.get_globals(), key=lambda item: item.unique_name):
        update(
            "global",
            construct.unique_name,
            construct.file_path,
            construct.name,
            construct.line_number,
            construct.initializer,
            ",".join(construct.referenced_functions or ()),
        )
        for reference in construct.references:
            update(
                "global_reference",
                construct.unique_name,
                reference.symbol,
                reference.line,
                reference.start_byte,
                reference.end_byte,
                repr(reference.target_ids),
            )
    for name, locations in sorted(graph.public_declarations.items()):
        update("public_declaration", name, ",".join(sorted(locations)))
    return digest.hexdigest()


def _normalize_file_ref(value):
    return str(value or "").replace("\\", "/")


def _same_file(a, b):
    return _normalize_file_ref(a) == _normalize_file_ref(b)


def function_for_location(
    graph: CodeGraph,
    file_path: str,
    line: int,
    *,
    symbol: str = "",
) -> FunctionNode | None:
    nodes = graph.get_file_nodes(file_path)
    if not nodes:
        return None
    line = max(1, int(line or 1))
    containing = [
        node
        for node in nodes
        if int(node.line_number or 0)
        <= line
        <= int(node.end_line or node.line_number or 0)
    ]
    if not containing:
        return None
    if symbol:
        exact = [
            node
            for node in containing
            if symbol in {node.unique_name, node.name}
            or node.unique_name.endswith(f"::{symbol}")
        ]
        if exact:
            containing = exact
    return max(containing, key=lambda node: int(node.line_number or 0))


def _node_sort_key(graph, node_or_name):
    node = (
        graph.get_node(node_or_name) if isinstance(node_or_name, str) else node_or_name
    )
    if not node:
        return ("", 0, str(node_or_name or ""))
    return (
        _normalize_file_ref(node.file_path),
        int(node.line_number or 0),
        node.name,
        node.unique_name,
    )


def _copy_graph_nodes(graph, node_names):
    focus = CodeGraph()
    selected = {name for name in node_names if name in graph.nodes}
    for unique_name in sorted(selected):
        node = graph.get_node(unique_name)
        if not node:
            continue
        call_sites = [
            replace(
                call,
                target_ids=tuple(
                    target for target in call.target_ids if target in selected
                ),
                targets_complete=(
                    call.targets_complete
                    and all(target in selected for target in call.target_ids)
                ),
            )
            for call in node.call_sites
        ]
        references = [
            replace(
                reference,
                target_ids=tuple(
                    target for target in reference.target_ids if target in selected
                ),
            )
            for reference in node.references
        ]
        focus.add_node(
            replace(
                node,
                calls=list(node.calls or []),
                resolved_calls=[
                    target for target in node.resolved_calls if target in selected
                ],
                call_sites=call_sites,
                references=references,
                lock_events=list(node.lock_events),
                tags=dict(node.tags),
                parameters=node.parameters,
                assignments=list(node.assignments),
                loops=list(node.loops),
                returns=list(node.returns),
            )
        )
    needed_files = {node.file_path for node in focus.nodes.values()}
    for global_construct in graph.get_globals():
        if global_construct.file_path in needed_files:
            focus.add_global(
                replace(
                    global_construct,
                    referenced_functions=list(
                        global_construct.referenced_functions or []
                    ),
                    references=[
                        replace(
                            reference,
                            target_ids=tuple(
                                target
                                for target in reference.target_ids
                                if target in selected
                            ),
                        )
                        for reference in global_construct.references
                    ],
                )
            )
    return focus


def _select_diverse_paths(
    paths: Sequence[ReachabilityPath],
    graph: CodeGraph,
    *,
    group_by: Literal["source", "sink"],
    max_paths: int,
    max_groups: int = 0,
    max_per_group: int = 0,
    max_variants_per_boundary: int = 0,
) -> list[ReachabilityPath]:
    unique_paths = _dedupe_paths(paths)
    if not unique_paths:
        return []
    diversity_by: Literal["source", "sink"] = "source" if group_by == "sink" else "sink"
    grouped: dict[str, list[ReachabilityPath]] = defaultdict(list)
    for path in unique_paths:
        grouped[getattr(path, group_by)].append(path)

    def rank(path: ReachabilityPath) -> tuple:
        return _confirmation_path_rank(path, graph)

    ordered_groups: list[list[ReachabilityPath]] = []
    for group_paths in grouped.values():
        by_boundary: dict[str, list[ReachabilityPath]] = defaultdict(list)
        for path in sorted(group_paths, key=rank):
            boundary_paths = by_boundary[getattr(path, diversity_by)]
            if (
                max_variants_per_boundary <= 0
                or len(boundary_paths) < max_variants_per_boundary
            ):
                boundary_paths.append(path)
        boundary_groups = sorted(by_boundary.values(), key=lambda items: rank(items[0]))
        ordered: list[ReachabilityPath] = []
        route_index = 0
        while boundary_groups:
            next_boundary_groups: list[list[ReachabilityPath]] = []
            for boundary_paths in boundary_groups:
                if route_index < len(boundary_paths):
                    ordered.append(boundary_paths[route_index])
                if route_index + 1 < len(boundary_paths):
                    next_boundary_groups.append(boundary_paths)
            boundary_groups = next_boundary_groups
            route_index += 1
        if max_per_group > 0:
            ordered = ordered[:max_per_group]
        ordered_groups.append(ordered)

    ordered_groups.sort(key=lambda items: rank(items[0]))
    if max_groups > 0:
        ordered_groups = ordered_groups[:max_groups]

    selected: list[ReachabilityPath] = []
    path_index = 0
    while ordered_groups and (max_paths <= 0 or len(selected) < max_paths):
        next_groups: list[list[ReachabilityPath]] = []
        for group_paths in ordered_groups:
            if path_index < len(group_paths):
                selected.append(group_paths[path_index])
                if max_paths > 0 and len(selected) >= max_paths:
                    return selected
            if path_index + 1 < len(group_paths):
                next_groups.append(group_paths)
        ordered_groups = next_groups
        path_index += 1
    return selected


def _confirmation_path_rank(path, graph):
    node_names = list(path.path or [])
    nodes = [graph.get_node(name) for name in node_names]
    nodes = [node for node in nodes if node is not None]
    endpoint = graph.get_node(path.sink)
    sink_count = sum(1 for node in nodes if node.is_sink)
    source = graph.get_node(path.source)
    return (
        -sink_count,
        -int(bool(endpoint and endpoint.is_sink)),
        -int(bool(endpoint and endpoint.sink_type and endpoint.sink_type != "other")),
        len(node_names),
        endpoint.file_path if endpoint else "",
        int(endpoint.line_number or 0) if endpoint else 0,
        source.file_path if source else "",
        int(source.line_number or 0) if source else 0,
        tuple(node_names),
    )
