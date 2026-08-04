# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import os
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import CodeGraphProviderContext
from metis.engine.codegraph import CodeGraphResult
from metis.engine.codegraph import FunctionNode
from metis.engine.codegraph import GlobalConstruct
from metis.engine.codegraph import LockEvent
from metis.engine.nodes.codegraph.progress import CODEGRAPH_PROGRESS
from metis.engine.nodes.codegraph.annotations import (
    GLOBAL_INITIALIZER_ENTRYPOINT_REASON,
)
from metis.engine.source.tree_sitter_nodes import (
    _identifier_from_node,
    _node_child_by_field_name,
    _node_children,
    _node_end_line,
    _node_kind,
    _node_line,
    _node_text,
)

from .ast import ANONYMOUS_NAMESPACE_SCOPE
from .ast import CFamilyAstMixin
from .ast import CFamilyCallSite
from .ast import CFamilyFunctionSyntax
from .runtime import TreeSitterRuntime
from .rules import CONTROL_CALLS
from .rules import LOCK_CALLS
from .rules import UNLOCK_CALLS
from .rules import normalize_lock_expression


@dataclass
class ParsedFunction:
    node: FunctionNode
    syntax: CFamilyFunctionSyntax
    calls: tuple[CFamilyCallSite, ...]


@dataclass
class ParsedFileGraph:
    functions: list[ParsedFunction] = field(default_factory=list)
    declarations: list[CFamilyFunctionSyntax] = field(default_factory=list)
    globals: list[GlobalConstruct] = field(default_factory=list)
    public_declarations: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class CFamilyCodeGraphProvider:
    def __init__(self, context: CodeGraphProviderContext) -> None:
        self._extractor = CFamilyTreeSitterExtractor(context)

    def build_graph(
        self,
        *,
        codebase_path: str,
        files: tuple[str, ...],
        progress_callback: Callable[[dict[str, object]], None] | None = None,
    ) -> CodeGraphResult:
        graph: CodeGraph = CodeGraph()
        functions: list[ParsedFunction] = []
        declarations: list[CFamilyFunctionSyntax] = []
        diagnostics: list[CodeGraphDiagnostic] = []
        processed_files: list[str] = []
        failed_files: list[str] = []
        selected_files = tuple(sorted(str(file) for file in files))
        total = len(selected_files)
        for completed, file_path in enumerate(selected_files, start=1):
            parsed = ParsedFileGraph()
            error_messages: tuple[str, ...] = ()
            try:
                parsed = self._extractor.parse_file(
                    codebase_path=codebase_path,
                    file_path=file_path,
                )
                error_messages = tuple(parsed.errors)
                if not error_messages:
                    file_graph = CodeGraph()
                    for function in parsed.functions:
                        file_graph.add_node(function.node)
                    for global_construct in parsed.globals:
                        file_graph.add_global(global_construct)
                    file_graph.add_public_declarations(parsed.public_declarations)
                    graph.merge(file_graph)
            except Exception as exc:
                error_messages = (f"{type(exc).__name__}: {exc}",)

            if error_messages:
                diagnostics.extend(
                    CodeGraphDiagnostic(file_path=file_path, message=message)
                    for message in error_messages
                )
                failed_files.append(file_path)
                function_count = 0
                global_count = 0
            else:
                processed_files.append(file_path)
                function_count = len(parsed.functions)
                global_count = len(parsed.globals)
                functions.extend(parsed.functions)
                declarations.extend(parsed.declarations)
            if progress_callback is not None:
                progress_callback(
                    {
                        "event": CODEGRAPH_PROGRESS,
                        "completed": completed,
                        "total": total,
                        "file": file_path,
                        "functions": function_count,
                        "globals": global_count,
                        "errors": len(error_messages),
                        "error_messages": error_messages,
                    }
                )

        _resolve_calls(graph, functions, declarations)
        graph.annotate_public_entrypoints()
        return CodeGraphResult(
            graph=graph,
            processed_files=tuple(processed_files),
            diagnostics=tuple(diagnostics),
            failed_files=tuple(failed_files),
        )


class CFamilyTreeSitterExtractor(CFamilyAstMixin):
    def __init__(self, context: CodeGraphProviderContext) -> None:
        self._context = context
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
        functions = self._collect_functions(root, source, rel_path, language)
        declarations = (
            self._collect_function_declarations(root, source)
            if language == "cpp"
            else []
        )
        function_ids = {function.node.unique_name for function in functions}
        global_constructs, global_function_refs = self._collect_globals(
            root,
            source,
            rel_path,
            function_ids=function_ids,
            include_nested=language == "c",
        )
        public_declarations = self._collect_public_function_declarations(
            root, source, rel_path
        )
        for function in functions:
            node = function.node
            if node.name in global_function_refs:
                node.is_public_entrypoint = True
                node.entrypoint_reason = GLOBAL_INITIALIZER_ENTRYPOINT_REASON
        return ParsedFileGraph(
            functions=functions,
            declarations=declarations,
            globals=global_constructs,
            public_declarations=public_declarations,
        )

    def _collect_functions(
        self,
        root: Any,
        source: bytes,
        rel_path: str,
        language: str = "c",
    ) -> list[ParsedFunction]:
        functions: list[ParsedFunction] = []
        seen: set[str] = set()

        for node in self._iter_function_definitions(root, include_methods=True):
            syntax: CFamilyFunctionSyntax | None
            if language == "c":
                declarator = _node_child_by_field_name(node, "declarator")
                name = _identifier_from_node(declarator or node, source)
                if not name:
                    continue
                syntax = CFamilyFunctionSyntax(
                    name=name,
                    qualified_name=name,
                    signature_suffix="",
                    lexical_scope=(),
                    minimum_argument_count=0,
                    maximum_argument_count=None,
                )
            else:
                syntax = self._function_syntax(node, source)
            if syntax is None:
                continue
            unique = (
                f"{rel_path}::{syntax.qualified_name}{syntax.signature_suffix}"
                if language == "cpp"
                else f"{rel_path}::{syntax.name}"
            )
            if unique in seen:
                continue
            seen.add(unique)
            call_sites = tuple(
                self._collect_calls_in_scope(
                    node,
                    source,
                    exclude_symbols=CONTROL_CALLS,
                    include_constructors=language == "cpp",
                    legacy_identifiers=language == "c",
                )
            )
            has_internal_linkage = self._has_internal_linkage(node, source)
            is_public_entrypoint = self._is_public_function_definition(
                node,
                source,
                rel_path,
                has_internal_linkage=has_internal_linkage,
            )
            functions.append(
                ParsedFunction(
                    node=FunctionNode(
                        unique,
                        rel_path,
                        syntax.name,
                        _node_line(node),
                        language=language,
                        calls=list(dict.fromkeys(call.symbol for call in call_sites)),
                        end_line=_node_end_line(node),
                        start_byte=int(node.start_byte()),
                        end_byte=int(node.end_byte()),
                        is_public_entrypoint=is_public_entrypoint,
                        entrypoint_reason=(
                            "non-static function definition"
                            if is_public_entrypoint
                            else ""
                        ),
                        has_internal_linkage=has_internal_linkage,
                        lock_events=self._collect_lock_events(node, source),
                    ),
                    syntax=syntax,
                    calls=call_sites,
                )
            )
        return sorted(
            functions,
            key=lambda item: (
                item.node.file_path,
                item.node.line_number,
                item.node.unique_name,
            ),
        )

    def _collect_function_declarations(
        self,
        root: Any,
        source: bytes,
    ) -> list[CFamilyFunctionSyntax]:
        declarations: list[CFamilyFunctionSyntax] = []
        for node in self._iter_nodes(root):
            if _node_kind(node) not in {"declaration", "field_declaration"}:
                continue
            syntax = self._function_syntax(node, source)
            if syntax is not None:
                declarations.append(syntax)
        return declarations

    def _collect_lock_events(
        self,
        scope_node: Any,
        source: bytes,
    ) -> list[LockEvent]:
        events: list[LockEvent] = []
        for call in self._iter_nodes(scope_node):
            if _node_kind(call) != "call_expression":
                continue
            callee_node = _node_child_by_field_name(call, "function")
            callee = _identifier_from_node(callee_node or call, source).lower()
            if callee not in LOCK_CALLS and callee not in UNLOCK_CALLS:
                continue
            argument = _first_argument(call)
            lock = normalize_lock_expression(_node_text(argument, source))
            if lock:
                events.append(
                    LockEvent(
                        operation="release" if callee in UNLOCK_CALLS else "acquire",
                        lock=lock,
                        line=_node_line(call),
                    )
                )
        return events

    def _collect_globals(
        self,
        root,
        source: bytes,
        rel_path: str,
        *,
        function_ids: set[str] | None = None,
        include_nested: bool = False,
    ) -> tuple[list[GlobalConstruct], set[str]]:
        globals_: list[GlobalConstruct] = []
        global_function_refs: set[str] = set()
        seen: set[str] = set()

        for node in self._iter_nodes(root):
            if _node_kind(node) != "init_declarator":
                continue
            if not include_nested:
                parent = node.parent()
                while parent is not None and _node_kind(parent) not in {
                    "class_specifier",
                    "compound_statement",
                    "struct_specifier",
                    "union_specifier",
                }:
                    parent = parent.parent()
                if parent is not None:
                    continue
            refs = self._global_function_references(node, source)
            if not refs:
                continue
            global_function_refs.update(refs)
            name = self._global_name(node, source) or f"global_{_node_line(node)}"
            unique = f"{rel_path}::{name}"
            if function_ids is not None and unique in function_ids:
                if not include_nested:
                    continue
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
        if self._has_anonymous_namespace_ancestor(node):
            return True
        if "static" not in self._declaration_words(node, source):
            return False
        parent = node.parent() if node is not None else None
        while parent is not None:
            if _node_kind(parent) in {
                "class_specifier",
                "struct_specifier",
                "union_specifier",
            }:
                return False
            parent = parent.parent()
        return True

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
        language = self._context.get_language_name_for_path(path)
        language = str(language or "").lower()
        if language in self._runtimes:
            return language
        return "c"

    def _has_file_role(self, path: str, role: str) -> bool:
        return self._context.has_language_file_role(path, role)

    def _rel_path(self, file_path: str, codebase_path: str) -> str:
        base = os.path.abspath(codebase_path)
        full = file_path if os.path.isabs(file_path) else os.path.join(base, file_path)
        return os.path.relpath(os.path.abspath(full), base).replace("\\", "/")


def _resolve_calls(
    graph: CodeGraph,
    functions: list[ParsedFunction],
    declarations: list[CFamilyFunctionSyntax],
) -> None:
    graph.resolve_all_calls()
    definitions_by_name: dict[str, list[ParsedFunction]] = {}
    definitions_by_qualified_name: dict[str, list[ParsedFunction]] = {}
    for function in functions:
        definitions_by_name.setdefault(function.node.name, []).append(function)
        definitions_by_qualified_name.setdefault(
            function.syntax.qualified_name, []
        ).append(function)
        if ANONYMOUS_NAMESPACE_SCOPE in function.syntax.lexical_scope:
            visible_name = "::".join(
                part
                for part in function.syntax.qualified_name.split("::")
                if part != ANONYMOUS_NAMESPACE_SCOPE
            )
            definitions_by_qualified_name.setdefault(visible_name, []).append(function)
    declared_minimums: dict[tuple[str, str], int] = {}
    for declaration in declarations:
        key = (declaration.qualified_name, declaration.signature_suffix)
        current = declared_minimums.get(key, declaration.minimum_argument_count)
        declared_minimums[key] = min(current, declaration.minimum_argument_count)

    for caller in functions:
        if caller.node.language != "cpp":
            continue
        resolved: list[str] = []
        for call in caller.calls:
            candidates = _call_candidates(
                call,
                caller,
                definitions_by_name,
                definitions_by_qualified_name,
                declared_minimums,
            )
            resolved.extend(candidate.node.unique_name for candidate in candidates)
        caller.node.resolved_calls = list(dict.fromkeys(resolved))


def _call_candidates(
    call: CFamilyCallSite,
    caller: ParsedFunction,
    definitions_by_name: dict[str, list[ParsedFunction]],
    definitions_by_qualified_name: dict[str, list[ParsedFunction]],
    declared_minimums: dict[tuple[str, str], int],
) -> list[ParsedFunction]:
    candidates: list[ParsedFunction] = []
    if call.qualified_name:
        qualified_names = tuple(
            dict.fromkeys((call.qualified_name, call.generic_qualified_name))
        )
        for qualified_name in qualified_names:
            normalized_name = qualified_name.removeprefix("::")
            candidate_names = [normalized_name]
            if not qualified_name.startswith("::"):
                candidate_names = [
                    "::".join((*caller.syntax.lexical_scope[:depth], normalized_name))
                    for depth in range(len(caller.syntax.lexical_scope), -1, -1)
                ]
            for candidate_name in candidate_names:
                candidates = definitions_by_qualified_name.get(candidate_name, [])
                if candidates:
                    break
            if candidates:
                break
    elif call.receiver == "this":
        member_scope = caller.syntax.qualified_name.rpartition("::")[0]
        candidates = definitions_by_qualified_name.get(
            f"{member_scope}::{call.symbol}", []
        )
    elif call.receiver:
        return []
    elif not call.receiver:
        for depth in range(len(caller.syntax.lexical_scope), -1, -1):
            candidate_name = "::".join(
                (*caller.syntax.lexical_scope[:depth], call.symbol)
            )
            candidates = definitions_by_qualified_name.get(candidate_name, [])
            if candidates:
                break

    if not candidates and call.qualified_name:
        return []
    if not candidates:
        candidates = list(definitions_by_name.get(call.symbol, []))

    candidates = [
        candidate
        for candidate in candidates
        if not candidate.node.has_internal_linkage
        or candidate.node.file_path == caller.node.file_path
    ]
    if not call.qualified_name:
        visible_candidates: list[ParsedFunction] = []
        for candidate in candidates:
            scope = candidate.syntax.lexical_scope
            if ANONYMOUS_NAMESPACE_SCOPE not in scope:
                visible_candidates.append(candidate)
                continue
            enclosing_scope = scope[: scope.index(ANONYMOUS_NAMESPACE_SCOPE)]
            if caller.syntax.lexical_scope[: len(enclosing_scope)] == enclosing_scope:
                visible_candidates.append(candidate)
        candidates = visible_candidates
        same_file = [
            candidate
            for candidate in candidates
            if candidate.node.file_path == caller.node.file_path
        ]
        if same_file:
            candidates = same_file

    return [
        candidate
        for candidate in candidates
        if declared_minimums.get(
            (candidate.syntax.qualified_name, candidate.syntax.signature_suffix),
            candidate.syntax.minimum_argument_count,
        )
        <= call.argument_count
        and (
            candidate.syntax.maximum_argument_count is None
            or call.argument_count <= candidate.syntax.maximum_argument_count
        )
    ]


def _first_argument(call_node: Any) -> Any | None:
    arguments = _node_child_by_field_name(call_node, "arguments")
    if arguments is None:
        return None
    for child in _node_children(arguments):
        if _node_kind(child) not in {"(", ")", ",", "comment"}:
            return child
    return None
