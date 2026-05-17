# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Small graph and finding records shared by reachability implementations."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FunctionNode:
    """Function-level call-graph node keyed as ``relative/path.c::symbol``."""

    unique_name: str
    file_path: str
    name: str
    line_number: int
    is_source: bool
    is_sink: bool
    calls: list[str] = field(default_factory=list)
    resolved_calls: list[str] = field(default_factory=list)
    source_reason: str = ""
    sink_type: str = ""
    sink_reason: str = ""


@dataclass
class GlobalConstruct:
    unique_name: str
    file_path: str
    name: str
    line_number: int
    kind: str
    initializer: str = ""
    referenced_functions: list[str] = field(default_factory=list)


@dataclass
class ReachabilityPath:
    source: str
    sink: str
    path: list[str] = field(default_factory=list)
    sink_type: str = ""


@dataclass
class VulnerabilityFinding:
    """Internal finding model before conversion to the legacy review JSON shape."""

    id: str
    vulnerability_type: str
    severity: str
    confidence: str
    source_function: str
    source_file: str
    source_line: int
    sink_function: str
    sink_file: str
    sink_line: int
    path: list[str] = field(default_factory=list)
    description: str = ""
    root_cause: str = ""
    evidence: str = ""
    mitigation: str = ""
    analysis_type: str = "reachability"
    primary_file: str = ""
    primary_function: str = ""
    primary_line: int = 0
    canonical_key: str = ""

    def __post_init__(self):
        if not self.primary_file:
            self.primary_file = self.sink_file or self.source_file
        if not self.primary_function:
            self.primary_function = self.sink_function or self.source_function
        if not self.primary_line:
            self.primary_line = self.sink_line or self.source_line or 0


class ReachabilityGraph:
    """Mutable call graph with best-effort name-based call resolution."""

    def __init__(self):
        self.nodes: dict[str, FunctionNode] = {}
        self.name_index: dict[str, list[str]] = {}
        self.globals: dict[str, GlobalConstruct] = {}

    def add_node(self, node):
        self.nodes[node.unique_name] = node
        self.name_index.setdefault(node.name, []).append(node.unique_name)

    def add_global(self, construct):
        self.globals[construct.unique_name] = construct

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

    def unresolved_calls_for(self, node):
        return [
            str(call)
            for call in node.calls or []
            if call and not self.name_index.get(str(call))
        ]

    def annotate_automatic_sources(self):
        """Mark graph roots as sources after calls have been resolved."""
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
            node.source_reason = (
                "no resolved internal callers in tree-sitter call graph"
            )
            updated += 1
        return updated

    def annotate_external_call_sinks(self, classify_call):
        """Mark functions that call known unresolved external APIs as sinks."""
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
        """Return all nodes in a given file."""
        return [n for n in self.nodes.values() if n.file_path == file_path]
