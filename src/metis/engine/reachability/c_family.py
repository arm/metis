# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from dataclasses import dataclass, field
import os

from .c_family_nodes import (
    _identifier_from_node,
    _node_child_by_field_name,
    _node_end_line,
    _node_kind,
    _node_line,
    _node_text,
)
from .c_family_ast import CFamilyAstMixin
from .treesitter_runtime import TreeSitterRuntime

from .domain import FunctionNode, GlobalConstruct
from .c_family_rules import CONTROL_CALLS


@dataclass
class ParsedFileGraph:
    nodes: list[FunctionNode] = field(default_factory=list)
    globals: list[GlobalConstruct] = field(default_factory=list)
    public_declarations: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class CFamilyTreeSitterExtractor(CFamilyAstMixin):
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
        nodes = self._collect_function_nodes(root, source, rel_path, language)
        global_constructs, global_function_refs = self._collect_globals(
            root, source, rel_path
        )
        public_declarations = self._collect_public_function_declarations(
            root, source, rel_path
        )
        for node in nodes:
            if node.name in global_function_refs:
                node.is_source = True
                node.is_public_entrypoint = True
                node.source_reason = (
                    "public_or_external_entrypoint: "
                    "referenced by a global function table or initializer"
                )
                node.entrypoint_reason = (
                    "referenced by a global function table or initializer"
                )
        return ParsedFileGraph(
            nodes=nodes,
            globals=global_constructs,
            public_declarations=public_declarations,
        )

    def _collect_function_nodes(
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
            has_internal_linkage = self._has_internal_linkage(node, source)
            is_public_entrypoint = self._is_public_function_definition(
                node,
                source,
                rel_path,
                has_internal_linkage=has_internal_linkage,
            )
            nodes.append(
                FunctionNode(
                    unique,
                    rel_path,
                    name,
                    _node_line(node),
                    False,
                    False,
                    language=language,
                    calls=calls,
                    end_line=_node_end_line(node),
                    start_byte=int(node.start_byte()),
                    end_byte=int(node.end_byte()),
                    is_public_entrypoint=is_public_entrypoint,
                    entrypoint_reason=(
                        "non-static function definition" if is_public_entrypoint else ""
                    ),
                    has_internal_linkage=has_internal_linkage,
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
                        unique,
                        rel_path,
                        name,
                        _node_line(node),
                        initializer=_node_text(node, source)[:2000],
                        referenced_functions=refs,
                    )
                )
            global_function_refs.update(refs)
        return globals_, global_function_refs

    def _collect_public_function_declarations(
        self,
        root,
        source: bytes,
        rel_path: str,
    ) -> dict[str, list[str]]:
        if not self._has_file_role(rel_path, "header"):
            return {}
        declarations: dict[str, list[str]] = {}
        for node in self._iter_nodes(root):
            if _node_kind(node) != "declaration":
                continue
            declarator = _node_child_by_field_name(node, "declarator")
            if declarator is None or not self._contains_kind(
                declarator, "function_declarator"
            ):
                continue
            name = _identifier_from_node(declarator, source)
            if not name or self._is_static_or_typedef(node, source):
                continue
            location = f"{rel_path}:{_node_line(node)}"
            declarations.setdefault(name, []).append(location)
        return declarations

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

    def _is_public_function_definition(
        self,
        node,
        source: bytes,
        rel_path: str,
        *,
        has_internal_linkage: bool | None = None,
    ) -> bool:
        if _node_kind(node) != "function_definition":
            return False
        if has_internal_linkage is None:
            has_internal_linkage = self._has_internal_linkage(node, source)
        if has_internal_linkage or self._is_typedef(node, source):
            return False
        return self._has_file_role(rel_path, "source") or self._has_file_role(
            rel_path, "header"
        )

    def _is_static_or_typedef(self, node, source: bytes) -> bool:
        return self._has_internal_linkage(node, source) or self._is_typedef(
            node, source
        )

    def _has_internal_linkage(self, node, source: bytes) -> bool:
        return "static" in self._declaration_words(node, source)

    def _is_typedef(self, node, source: bytes) -> bool:
        return "typedef" in self._declaration_words(node, source)

    def _declaration_words(self, node, source: bytes) -> set[str]:
        prefix = self._declaration_prefix(node, source)
        return set(prefix.replace("\n", " ").split())

    def _declaration_prefix(self, node, source: bytes) -> str:
        declarator = _node_child_by_field_name(node, "declarator")
        if declarator is not None:
            start = int(node.start_byte())
            end = int(declarator.start_byte())
            if end > start:
                return source[start:end].decode("utf-8", errors="ignore")
        text = _node_text(node, source)
        name = _identifier_from_node(declarator or node, source)
        if name and name in text:
            return text.split(name, 1)[0]
        return text.split("{", 1)[0].split(";", 1)[0]

    def _contains_kind(self, node, expected_kind: str) -> bool:
        return any(
            _node_kind(candidate) == expected_kind
            for candidate in self._iter_nodes(node)
        )

    def _language_for_file(self, path: str) -> str:
        get_language_name_for_path = getattr(
            self._repository,
            "get_language_name_for_path",
            None,
        )
        language = (
            get_language_name_for_path(path)
            if callable(get_language_name_for_path)
            else ""
        )
        language = str(language or "").lower()
        if language in self._runtimes:
            return language
        return "c"

    def _has_file_role(self, path: str, role: str) -> bool:
        has_language_file_role = getattr(
            getattr(self, "_repository", None),
            "has_language_file_role",
            None,
        )
        return bool(
            callable(has_language_file_role) and has_language_file_role(path, role)
        )

    def _rel_path(self, file_path: str, codebase_path: str) -> str:
        base = os.path.abspath(codebase_path)
        full = file_path if os.path.isabs(file_path) else os.path.join(base, file_path)
        return os.path.relpath(os.path.abspath(full), base).replace("\\", "/")
