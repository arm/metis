# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Small graph and finding records shared by reachability implementations."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


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

    def to_dict(self) -> dict:
        return {
            "unique_name": self.unique_name, "file_path": self.file_path,
            "name": self.name, "line_number": self.line_number,
            "is_source": self.is_source, "is_sink": self.is_sink,
            "calls": self.calls, "resolved_calls": self.resolved_calls,
            "source_reason": self.source_reason, "sink_type": self.sink_type,
            "sink_reason": self.sink_reason,
        }


@dataclass
class GlobalConstruct:
    unique_name: str
    file_path: str
    name: str
    line_number: int
    kind: str
    initializer: str = ""
    referenced_functions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "unique_name": self.unique_name, "file_path": self.file_path,
            "name": self.name, "line_number": self.line_number,
            "kind": self.kind, "initializer": self.initializer,
            "referenced_functions": self.referenced_functions,
        }


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

    def to_dict(self) -> dict:
        return {
            "id": self.id, "vulnerability_type": self.vulnerability_type,
            "severity": self.severity, "confidence": self.confidence,
            "source_function": self.source_function, "source_file": self.source_file,
            "source_line": self.source_line, "sink_function": self.sink_function,
            "sink_file": self.sink_file, "sink_line": self.sink_line,
            "path": self.path, "description": self.description,
            "root_cause": self.root_cause, "evidence": self.evidence,
            "analysis_type": self.analysis_type,
            "primary_file": self.primary_file, "primary_function": self.primary_function,
            "primary_line": self.primary_line, "canonical_key": self.canonical_key,
        }


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

    def get_sources(self): return [n for n in self.nodes.values() if n.is_source]
    def get_sinks(self): return [n for n in self.nodes.values() if n.is_sink]
    def get_node(self, name): return self.nodes.get(name)
    def get_globals(self): return list(self.globals.values())
    def node_count(self): return len(self.nodes)
    def edge_count(self): return sum(len(n.resolved_calls) for n in self.nodes.values())

    def get_callers(self, target_unique_name):
        """Return nodes that have target in their resolved_calls."""
        return [n for n in self.nodes.values() if target_unique_name in n.resolved_calls]

    def get_file_nodes(self, file_path):
        """Return all nodes in a given file."""
        return [n for n in self.nodes.values() if n.file_path == file_path]

    def save_jsonl(self, path, *, include_globals=False):
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            for n in self.nodes.values():
                row = n.to_dict()
                if include_globals:
                    row["record_type"] = "function"
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            if include_globals:
                for g in self.globals.values():
                    row = g.to_dict()
                    row["record_type"] = "global"
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    @classmethod
    def load_jsonl(cls, path):
        """Load a previously saved graph from JSONL."""
        graph = cls()
        p = Path(path)
        if not p.exists():
            return graph
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                if d.get("record_type") == "global":
                    graph.add_global(GlobalConstruct(
                        unique_name=d["unique_name"], file_path=d["file_path"],
                        name=d["name"], line_number=d["line_number"],
                        kind=d.get("kind", ""),
                        initializer=d.get("initializer", ""),
                        referenced_functions=d.get("referenced_functions", []),
                    ))
                    continue
                node = FunctionNode(
                    unique_name=d["unique_name"], file_path=d["file_path"],
                    name=d["name"], line_number=d["line_number"],
                    is_source=d["is_source"], is_sink=d["is_sink"],
                    calls=d.get("calls", []), resolved_calls=d.get("resolved_calls", []),
                    source_reason=d.get("source_reason", ""),
                    sink_type=d.get("sink_type", ""),
                    sink_reason=d.get("sink_reason", ""),
                )
                graph.add_node(node)
        # resolved_calls are already loaded; rebuild name_index only
        return graph
