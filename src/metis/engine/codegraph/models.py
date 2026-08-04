# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import os
from dataclasses import dataclass
from dataclasses import field
from dataclasses import replace
from typing import Literal


@dataclass(frozen=True, slots=True)
class LockEvent:
    operation: Literal["acquire", "release"]
    lock: str
    line: int


@dataclass(frozen=True, slots=True)
class Tag:
    value: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not isinstance(self.reason, str):
            raise TypeError("Tag value and reason must be strings")


@dataclass
class FunctionNode:
    unique_name: str
    file_path: str
    name: str
    line_number: int
    language: str = ""
    calls: list[str] = field(default_factory=list)
    resolved_calls: list[str] = field(default_factory=list)
    end_line: int = 0
    start_byte: int = 0
    end_byte: int = 0
    is_public_entrypoint: bool = False
    entrypoint_reason: str = ""
    has_internal_linkage: bool = False
    is_source: bool = False
    source_reason: str = ""
    is_sink: bool = False
    sink_type: str = ""
    sink_reason: str = ""
    lock_events: list[LockEvent] = field(default_factory=list)
    tags: dict[str, Tag] = field(default_factory=dict)

    def set_tag(self, key: str, *, value: str = "", reason: str = "") -> None:
        if not key or not key.replace(".", "_").isidentifier():
            raise ValueError(f"Invalid tag key {key!r}")
        self.tags[key] = Tag(value=value, reason=reason)

    def has_tag(self, key: str) -> bool:
        return key in self.tags

    @property
    def anchor(self):
        from metis.engine.source.anchor import KIND_FUNCTION, CodeAnchor, content_hash

        return CodeAnchor(
            file_path=self.file_path,
            start_line=self.line_number,
            end_line=self.end_line or self.line_number,
            start_byte=self.start_byte,
            end_byte=self.end_byte,
            symbol=self.unique_name,
            kind=KIND_FUNCTION,
            content_hash=content_hash(self.name),
        )


@dataclass
class GlobalConstruct:
    unique_name: str
    file_path: str
    name: str
    line_number: int
    initializer: str = ""
    referenced_functions: list[str] = field(default_factory=list)


class CodeGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, FunctionNode] = {}
        self.name_index: dict[str, list[str]] = {}
        self.globals: dict[str, GlobalConstruct] = {}
        self.public_declarations: dict[str, list[str]] = {}

    def add_node(self, node: FunctionNode) -> None:
        if node.unique_name in self.nodes:
            raise ValueError(f"Duplicate code graph node ID: {node.unique_name!r}")
        self.nodes[node.unique_name] = node
        self.name_index.setdefault(node.name, []).append(node.unique_name)

    def add_global(self, construct: GlobalConstruct) -> None:
        if construct.unique_name in self.globals:
            raise ValueError(
                f"Duplicate code graph global ID: {construct.unique_name!r}"
            )
        self.globals[construct.unique_name] = construct

    def add_public_declarations(
        self,
        declarations: dict[str, list[str]],
    ) -> None:
        for name, locations in dict(declarations or {}).items():
            name = str(name or "").strip()
            if not name:
                continue
            existing = self.public_declarations.setdefault(name, [])
            for location in locations or []:
                location = str(location or "").strip()
                if location and location not in existing:
                    existing.append(location)

    def resolve_all_calls(self) -> None:
        for node in self.nodes.values():
            resolved = []
            for call_name in node.calls:
                targets = self.name_index.get(call_name, [])
                if len(targets) == 1:
                    resolved.append(targets[0])
                elif len(targets) > 1:
                    same = [
                        target
                        for target in targets
                        if self.nodes[target].file_path == node.file_path
                    ]
                    resolved.extend(same if same else targets)
            node.resolved_calls = list(dict.fromkeys(resolved))

    def annotate_public_entrypoints(self) -> int:
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
        return updated

    def unresolved_calls_for(self, node: FunctionNode) -> list[str]:
        resolved_names = {
            self.nodes[target].name
            for target in node.resolved_calls
            if target in self.nodes
        }
        return [
            str(call)
            for call in node.calls or []
            if call and str(call) not in resolved_names
        ]

    def get_node(self, name: str) -> FunctionNode | None:
        return self.nodes.get(name)

    def get_globals(self) -> list[GlobalConstruct]:
        return list(self.globals.values())

    def get_sources(self) -> list[FunctionNode]:
        return [node for node in self.nodes.values() if node.is_source]

    def node_count(self) -> int:
        return len(self.nodes)

    def edge_count(self) -> int:
        return sum(len(n.resolved_calls) for n in self.nodes.values())

    def get_file_nodes(self, file_path: str) -> list[FunctionNode]:
        return [n for n in self.nodes.values() if n.file_path == file_path]

    def merge(self, other: "CodeGraph") -> None:
        duplicate_nodes = set(self.nodes) & set(other.nodes)
        duplicate_globals = set(self.globals) & set(other.globals)
        if duplicate_nodes:
            duplicate = min(duplicate_nodes)
            raise ValueError(f"Duplicate code graph node ID: {duplicate!r}")
        if duplicate_globals:
            duplicate = min(duplicate_globals)
            raise ValueError(f"Duplicate code graph global ID: {duplicate!r}")
        for node in other.nodes.values():
            self.add_node(node)
        for construct in other.globals.values():
            self.add_global(construct)
        self.add_public_declarations(other.public_declarations)

    def copy(self) -> "CodeGraph":
        graph = CodeGraph()
        for node in self.nodes.values():
            graph.add_node(
                replace(
                    node,
                    calls=list(node.calls),
                    resolved_calls=list(node.resolved_calls),
                    lock_events=list(node.lock_events),
                    tags=dict(node.tags),
                )
            )
        for construct in self.globals.values():
            graph.add_global(
                replace(
                    construct,
                    referenced_functions=list(construct.referenced_functions),
                )
            )
        graph.add_public_declarations(self.public_declarations)
        return graph

    def validate_for_files(
        self,
        files: tuple[str, ...] | list[str],
        *,
        codebase_path: str,
    ) -> None:
        allowed_paths = {
            _normalized_file_path(path, codebase_path=codebase_path) for path in files
        }
        expected_name_index: dict[str, list[str]] = {}
        for node_id, node in self.nodes.items():
            if node.unique_name != node_id:
                raise ValueError(f"Code graph node index corruption for ID {node_id!r}")
            if node.is_source != bool(node.source_reason):
                raise ValueError(
                    f"Code graph node {node_id!r} has invalid source annotations"
                )
            if node.is_sink != bool(node.sink_type and node.sink_reason):
                raise ValueError(
                    f"Code graph node {node_id!r} has invalid sink annotations"
                )
            if not isinstance(node.tags, dict) or not all(
                isinstance(key, str) and isinstance(tag, Tag)
                for key, tag in node.tags.items()
            ):
                raise ValueError(f"Code graph node {node_id!r} has invalid tags")
            if (
                _normalized_file_path(node.file_path, codebase_path=codebase_path)
                not in allowed_paths
            ):
                raise ValueError(
                    f"Code graph node {node_id!r} belongs to unrequested file "
                    f"{node.file_path!r}"
                )
            expected_name_index.setdefault(node.name, []).append(node_id)
            invalid_targets = [
                target for target in node.resolved_calls if target not in self.nodes
            ]
            if invalid_targets:
                raise ValueError(
                    f"Code graph node {node_id!r} has invalid resolved targets: "
                    + ", ".join(invalid_targets)
                )
        if self.name_index != expected_name_index:
            raise ValueError("Code graph name index is corrupt")

        for global_id, construct in self.globals.items():
            if construct.unique_name != global_id:
                raise ValueError(
                    f"Code graph global index corruption for ID {global_id!r}"
                )
            if (
                _normalized_file_path(construct.file_path, codebase_path=codebase_path)
                not in allowed_paths
            ):
                raise ValueError(
                    f"Code graph global {global_id!r} belongs to unrequested file "
                    f"{construct.file_path!r}"
                )


def _normalized_file_path(path: str, *, codebase_path: str) -> str:
    value = str(path)
    if os.path.isabs(value):
        value = os.path.relpath(value, os.path.abspath(codebase_path))
    return os.path.normpath(value).replace("\\", "/")
