# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import replace
import hashlib

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph.queries import _build_reverse_edges as _build_reverse_edges
from metis.engine.codegraph.queries import (
    function_for_location as function_for_location,
)


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
