# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Tree-sitter extraction of C/C++ functions, calls, and entrypoint tables."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import re

from metis.engine.analysis.c_family_analyzer_common import (
    _identifier_from_node,
    _node_line,
    _node_text,
)
from metis.engine.analysis.c_family_ast import CFamilyAstMixin
from metis.engine.analysis.treesitter_runtime import TreeSitterRuntime
from metis.plugins.cpp_plugin import CppPlugin

from ..reachability_common.models import FunctionNode, GlobalConstruct
from .c_family_rules import (
    CONTROL_CALLS,
    ENTRYPOINT_FIELDS,
    is_sink_function,
    is_source_function,
)

_CPP_EXTENSIONS = frozenset(CppPlugin.DEFAULT_EXTENSIONS)


@dataclass
class ParsedFileGraph:
    nodes: list[FunctionNode] = field(default_factory=list)
    globals: list[GlobalConstruct] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class CFamilyTreeSitterExtractor(CFamilyAstMixin):
    """Convert one C-family source file into graph nodes plus global callbacks."""

    def __init__(self):
        self._runtimes = {
            "c": TreeSitterRuntime("c"),
            "cpp": TreeSitterRuntime("cpp"),
        }

    def parse_file(self, *, codebase_path: str, file_path: str) -> ParsedFileGraph:
        rel_path = self._rel_path(file_path, codebase_path)
        language = self._language_for_file(rel_path)
        runtime = self._runtimes.get(language)
        if runtime is None:
            return ParsedFileGraph(errors=[f"{rel_path}: unsupported extension"])
        if not runtime.is_available:
            return ParsedFileGraph(
                errors=[
                    f"{rel_path}: tree-sitter parser unavailable for {language}: "
                    f"{runtime.init_error or 'unknown error'}"
                ]
            )

        try:
            parsed = runtime.parse_file(codebase_path, rel_path)
        except Exception as exc:
            return ParsedFileGraph(errors=[f"{rel_path}: {type(exc).__name__}: {exc}"])

        source = bytes(parsed.text, "utf-8")
        root = parsed.tree.root_node
        global_constructs, entrypoint_refs = self._collect_globals(
            root, source, rel_path
        )
        nodes = self._collect_functions(root, source, rel_path, entrypoint_refs)
        return ParsedFileGraph(nodes=nodes, globals=global_constructs)

    def _collect_functions(
        self,
        root,
        source: bytes,
        rel_path: str,
        entrypoint_refs: set[str],
    ) -> list[FunctionNode]:
        nodes: list[FunctionNode] = []
        seen: set[str] = set()

        for node in self._iter_function_definitions(root, include_methods=True):
            name = self._function_name_from_definition(node, source)
            if name:
                unique = f"{rel_path}::{name}"
                if unique not in seen:
                    seen.add(unique)
                    calls = self._collect_call_symbols(node, source)
                    text = _node_text(node, source)
                    is_source, source_reason = is_source_function(
                        name, calls, entrypoint_refs
                    )
                    is_sink, sink_type, sink_reason = is_sink_function(
                        name, calls, text
                    )
                    nodes.append(
                        FunctionNode(
                            unique_name=unique,
                            file_path=rel_path,
                            name=name,
                            line_number=_node_line(node),
                            is_source=is_source,
                            is_sink=is_sink,
                            calls=calls,
                            source_reason=source_reason,
                            sink_type=sink_type,
                            sink_reason=sink_reason,
                        )
                    )
        return sorted(
            nodes, key=lambda item: (item.file_path, item.line_number, item.name)
        )

    def _collect_call_symbols(self, scope_node, source: bytes) -> list[str]:
        calls: list[str] = []
        seen: set[str] = set()
        for call in self._collect_calls_in_scope(
            scope_node, source, exclude_symbols=CONTROL_CALLS, sort=False
        ):
            if call.symbol in seen:
                continue
            seen.add(call.symbol)
            calls.append(call.symbol)
        return calls

    def _collect_globals(
        self,
        root,
        source: bytes,
        rel_path: str,
    ) -> tuple[list[GlobalConstruct], set[str]]:
        globals_: list[GlobalConstruct] = []
        entrypoint_refs: set[str] = set()
        seen: set[str] = set()

        for node in self._iter_nodes(root):
            node_type = str(getattr(node, "type", "") or "")
            if node_type in {"init_declarator", "declaration", "field_declaration"}:
                text = _node_text(node, source)
                refs = self._entrypoint_references(text)
                if refs:
                    name = (
                        self._global_name(node, source) or f"global_{_node_line(node)}"
                    )
                    unique = f"{rel_path}::{name}"
                    if unique not in seen:
                        seen.add(unique)
                        globals_.append(
                            GlobalConstruct(
                                unique_name=unique,
                                file_path=rel_path,
                                name=name,
                                line_number=_node_line(node),
                                kind=self._global_kind(text),
                                initializer=text[:2000],
                                referenced_functions=refs,
                            )
                        )
                    entrypoint_refs.update(refs)
        return globals_, entrypoint_refs

    def _entrypoint_references(self, text: str) -> list[str]:
        refs: list[str] = []
        seen: set[str] = set()
        for field_name, ref in re.findall(
            r"\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*&?\s*([A-Za-z_][A-Za-z0-9_]*)",
            text or "",
        ):
            if field_name not in ENTRYPOINT_FIELDS:
                continue
            if ref in seen:
                continue
            seen.add(ref)
            refs.append(ref)
        return refs

    def _global_name(self, node, source: bytes) -> str:
        declarator = self._field(node, "declarator")
        return _identifier_from_node(declarator or node, source)

    def _global_kind(self, text: str) -> str:
        lowered = str(text or "").lower()
        if "file_operations" in lowered or "fops" in lowered:
            return "file_operations"
        if "ops" in lowered:
            return "ops_table"
        if "timer" in lowered:
            return "timer"
        if "work" in lowered:
            return "workqueue"
        return "global_initializer"

    def _field(self, node, name: str):
        try:
            return node.child_by_field_name(name)
        except Exception:
            return None

    def _language_for_file(self, path: str) -> str:
        ext = os.path.splitext(path)[1].lower()
        if ext in _CPP_EXTENSIONS:
            return "cpp"
        return "c"

    def _rel_path(self, file_path: str, codebase_path: str) -> str:
        base = os.path.abspath(codebase_path)
        full = file_path if os.path.isabs(file_path) else os.path.join(base, file_path)
        return os.path.relpath(os.path.abspath(full), base).replace("\\", "/")
