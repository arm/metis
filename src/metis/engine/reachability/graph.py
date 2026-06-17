# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import replace

from .domain import FunctionNode, GlobalConstruct


class ReachabilityGraph:
    def __init__(self):
        self.nodes: dict[str, FunctionNode] = {}
        self.name_index: dict[str, list[str]] = {}
        self.globals: dict[str, GlobalConstruct] = {}
        self.public_declarations: dict[str, list[str]] = {}

    def add_node(self, node):
        self.nodes[node.unique_name] = node
        self.name_index.setdefault(node.name, []).append(node.unique_name)

    def add_global(self, construct):
        self.globals[construct.unique_name] = construct

    def add_public_declarations(self, declarations):
        for name, locations in dict(declarations or {}).items():
            name = str(name or "").strip()
            if not name:
                continue
            existing = self.public_declarations.setdefault(name, [])
            for location in locations or []:
                location = str(location or "").strip()
                if location and location not in existing:
                    existing.append(location)

    def resolve_all_calls(self):
        for node in self.nodes.values():
            resolved = []
            for call_name in node.calls:
                targets = self.name_index.get(call_name, [])
                if len(targets) == 1:
                    resolved.append(targets[0])
                elif len(targets) > 1:
                    same = [t for t in targets if t.startswith(node.file_path + "::")]
                    resolved.extend(same if same else targets)
            node.resolved_calls = list(dict.fromkeys(resolved))

    def annotate_public_entrypoints(self):
        updated = 0
        for node in self.nodes.values():
            reasons = []
            if node.entrypoint_reason:
                reasons.append(node.entrypoint_reason)
            declarations = (
                []
                if node.has_internal_linkage
                else self.public_declarations.get(node.name, [])
            )
            if declarations:
                reasons.append(
                    "declared in public header: " + ", ".join(declarations[:4])
                )
            if not reasons:
                continue
            reason = "; ".join(dict.fromkeys(reasons))
            if not node.is_public_entrypoint:
                node.is_public_entrypoint = True
                updated += 1
            node.entrypoint_reason = reason
            if node.is_source:
                node.source_reason = _public_entrypoint_reason(reason)
        return updated

    def unresolved_calls_for(self, node):
        return [
            str(call)
            for call in node.calls or []
            if call and not self.name_index.get(str(call))
        ]

    def annotate_automatic_sources(self):
        incoming = {name: set() for name in self.nodes}
        for caller in self.nodes.values():
            for callee in caller.resolved_calls or []:
                if callee in incoming and callee != caller.unique_name:
                    incoming[callee].add(caller.unique_name)

        updated = 0
        for name, node in self.nodes.items():
            if node.is_source or incoming[name]:
                continue
            node.is_source = True
            if node.is_public_entrypoint:
                node.source_reason = _public_entrypoint_reason(node.entrypoint_reason)
            else:
                node.source_reason = (
                    "no resolved internal callers in tree-sitter call graph"
                )
            updated += 1
        return updated

    def annotate_external_call_sinks(self, classify_call):
        updated = 0
        for node in self.nodes.values():
            if node.is_sink:
                continue
            for call in self.unresolved_calls_for(node):
                sink_type = classify_call(call)
                if not sink_type:
                    continue
                node.is_sink = True
                node.sink_type = sink_type
                node.sink_reason = f"calls external security API: {call}"
                updated += 1
                break
        return updated

    def get_sources(self):
        return [n for n in self.nodes.values() if n.is_source]

    def get_sinks(self):
        return [n for n in self.nodes.values() if n.is_sink]

    def get_node(self, name):
        return self.nodes.get(name)

    def get_globals(self):
        return list(self.globals.values())

    def node_count(self):
        return len(self.nodes)

    def edge_count(self):
        return sum(len(n.resolved_calls) for n in self.nodes.values())

    def get_file_nodes(self, file_path):
        return [n for n in self.nodes.values() if n.file_path == file_path]

    def copy(self):
        copied = ReachabilityGraph()
        for node in self.nodes.values():
            copied.add_node(
                replace(
                    node,
                    calls=list(node.calls or []),
                    resolved_calls=list(node.resolved_calls or []),
                )
            )
        for construct in self.globals.values():
            copied.add_global(
                replace(
                    construct,
                    referenced_functions=list(construct.referenced_functions or []),
                )
            )
        copied.add_public_declarations(
            {
                name: list(locations)
                for name, locations in self.public_declarations.items()
            }
        )
        return copied


def _public_entrypoint_reason(reason: str) -> str:
    reason = str(reason or "").strip()
    if reason:
        return f"public_or_external_entrypoint: {reason}"
    return "public_or_external_entrypoint"
