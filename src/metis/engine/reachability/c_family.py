# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Tree-sitter extraction of C/C++ functions, calls, and entrypoint tables."""

from __future__ import annotations

from dataclasses import dataclass, field
import os

from metis.engine.analysis.c_family_analyzer_common import (
    _identifier_from_node,
    _node_child_by_field_name,
    _node_kind,
    _node_line,
    _node_text,
)
from metis.engine.analysis.c_family_ast import CFamilyAstMixin
from metis.engine.analysis.treesitter_runtime import TreeSitterRuntime

from .models import FunctionNode, GlobalConstruct
from .c_family_rules import CONTROL_CALLS


@dataclass
class ParsedFileGraph:
    nodes: list[FunctionNode] = field(default_factory=list)
    globals: list[GlobalConstruct] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class CFamilyTreeSitterExtractor(CFamilyAstMixin):
    """Convert one C-family source file into graph nodes plus global callbacks."""

    def __init__(self, repository=None):
        self._repository = repository
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
        root = parsed.tree.root_node()
        nodes = self._collect_functions(root, source, rel_path, language)
        global_constructs, global_function_refs = self._collect_globals(
            root, source, rel_path
        )
        for node in nodes:
            if node.name in global_function_refs:
                node.is_source = True
                node.source_reason = (
                    "referenced by a global function table or initializer"
                )
        return ParsedFileGraph(nodes=nodes, globals=global_constructs)

    def _collect_functions(
        self,
        root,
        source: bytes,
        rel_path: str,
        language: str = "c",
    ) -> list[FunctionNode]:
        nodes: list[FunctionNode] = []
        seen: set[str] = set()

        for node in self._iter_function_definitions(root, include_methods=True):
            name = self._function_name_from_definition(node, source)
            if not name:
                continue
            unique = f"{rel_path}::{name}"
            if unique in seen:
                continue
            seen.add(unique)
            calls = self._collect_call_symbols(node, source)
            nodes.append(
                FunctionNode(
                    unique_name=unique,
                    file_path=rel_path,
                    name=name,
                    line_number=_node_line(node),
                    is_source=False,
                    is_sink=False,
                    language=language,
                    calls=calls,
                )
            )
        return sorted(
            nodes, key=lambda item: (item.file_path, item.line_number, item.name)
        )

    def _collect_call_symbols(self, scope_node, source: bytes) -> list[str]:
        calls: list[str] = []
        seen: set[str] = set()
        for call in self._collect_calls_in_scope(
            scope_node, source, exclude_symbols=CONTROL_CALLS
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
        global_function_refs: set[str] = set()
        seen: set[str] = set()

        for node in self._iter_nodes(root):
            if _node_kind(node) != "init_declarator":
                continue
            refs = self._global_function_references(node, source)
            if not refs:
                continue
            name = self._global_name(node, source) or f"global_{_node_line(node)}"
            unique = f"{rel_path}::{name}"
            if unique not in seen:
                seen.add(unique)
                globals_.append(
                    GlobalConstruct(
                        unique_name=unique,
                        file_path=rel_path,
                        name=name,
                        line_number=_node_line(node),
                        initializer=_node_text(node, source)[:2000],
                        referenced_functions=refs,
                    )
                )
            global_function_refs.update(refs)
        return globals_, global_function_refs

    def _global_function_references(self, node, source: bytes) -> list[str]:
        value = _node_child_by_field_name(node, "value")
        if value is None:
            return []
        refs = (
            _node_text(candidate, source).strip()
            for candidate in self._iter_nodes(value)
            if _node_kind(candidate) == "identifier"
        )
        return list(dict.fromkeys(ref for ref in refs if ref))

    def _global_name(self, node, source: bytes) -> str:
        declarator = _node_child_by_field_name(node, "declarator")
        return _identifier_from_node(declarator or node, source)

    def _language_for_file(self, path: str) -> str:
        plugin = None
        get_plugin_for_path = getattr(self._repository, "get_plugin_for_path", None)
        if callable(get_plugin_for_path):
            plugin = get_plugin_for_path(path)
        language = str(getattr(plugin, "get_name", lambda: "")() or "").lower()
        if language in self._runtimes:
            return language
        return "c"

    def _rel_path(self, file_path: str, codebase_path: str) -> str:
        base = os.path.abspath(codebase_path)
        full = file_path if os.path.isabs(file_path) else os.path.join(base, file_path)
        return os.path.relpath(os.path.abspath(full), base).replace("\\", "/")
