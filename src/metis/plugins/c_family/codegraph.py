# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import os
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field
from dataclasses import replace
from typing import Any
from typing import Literal

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import CodeGraphProviderContext
from metis.engine.codegraph import CodeGraphResult
from metis.engine.codegraph import FunctionNode
from metis.engine.codegraph import GlobalConstruct
from metis.engine.codegraph import LockEvent
from metis.engine.codegraph import SymbolReference
from metis.engine.nodes.codegraph.progress import CODEGRAPH_PROGRESS
from metis.engine.source.tree_sitter_nodes import _identifier_from_node
from metis.engine.source.tree_sitter_nodes import _node_child_by_field_name
from metis.engine.source.tree_sitter_nodes import _node_children
from metis.engine.source.tree_sitter_nodes import _node_end_line
from metis.engine.source.tree_sitter_nodes import _node_kind
from metis.engine.source.tree_sitter_nodes import _node_line
from metis.engine.source.tree_sitter_nodes import _node_text

from .ast import ANONYMOUS_NAMESPACE_SCOPE
from .ast import CFamilyAstMixin
from .ast import CFamilyFunctionSyntax
from .ast import _declarator_name_node
from .ast import _expression_children
from .ast import _lexical_scope
from .ast import _normalized_syntax
from .linking import ParsedFunction
from .linking import ValueBinding
from .linking import _resolve_calls
from .linking import _visible_value_binding
from .rules import CONTROL_CALLS
from .rules import LOCK_CALLS
from .rules import UNLOCK_CALLS
from .rules import normalize_lock_expression
from .runtime import TreeSitterRuntime
from .runtime import _MacroFunctionDefinition
from .runtime import _MacroFunctionMask

ValueDeclarationKind = Literal["function", "function_pointer", "unnamed", "value"]


@dataclass
class ParsedFileGraph:
    language: str = ""
    functions: list[ParsedFunction] = field(default_factory=list)
    declarations: list[CFamilyFunctionSyntax] = field(default_factory=list)
    globals: list[GlobalConstruct] = field(default_factory=list)
    global_scopes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    value_declarations: dict[tuple[str, str], list[int]] = field(default_factory=dict)
    public_declarations: dict[str, list[str]] = field(default_factory=dict)
    macro_function_definitions: tuple[_MacroFunctionDefinition, ...] = ()
    diagnostics: list[CodeGraphDiagnostic] = field(default_factory=list)
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
        global_languages: dict[str, str] = {}
        global_scopes: dict[str, tuple[str, ...]] = {}
        value_declarations: dict[tuple[str, str], list[int]] = {}
        diagnostics: list[CodeGraphDiagnostic] = []
        macro_function_definitions: list[_MacroFunctionDefinition] = []
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
                diagnostics.extend(parsed.diagnostics)
                error_messages = tuple(parsed.errors)
                if not error_messages:
                    file_graph = CodeGraph()
                    for function in parsed.functions:
                        file_graph.add_node(function.node)
                    for global_construct in parsed.globals:
                        file_graph.add_global(global_construct)
                        global_languages[global_construct.unique_name] = parsed.language
                        global_scopes[global_construct.unique_name] = (
                            parsed.global_scopes[global_construct.unique_name]
                        )
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
                macro_function_definitions.extend(parsed.macro_function_definitions)
                for key, offsets in parsed.value_declarations.items():
                    value_declarations.setdefault(key, []).extend(offsets)
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

        _annotate_macro_function_wrappers(functions, macro_function_definitions)
        _annotate_macro_passthrough_calls(functions, macro_function_definitions)
        _resolve_calls(
            graph,
            functions,
            declarations,
            global_languages,
            global_scopes,
            value_declarations,
        )
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

        source = parsed.parse_source
        root = parsed.tree.root_node()
        root_nodes = tuple(self._iter_nodes(root))
        diagnostics: list[CodeGraphDiagnostic] = []
        diagnostic_root = parsed.diagnostic_tree.root_node()
        if diagnostic_root.has_error():
            diagnostic_nodes = tuple(self._iter_nodes(diagnostic_root))
            syntax_error = next(
                (
                    node
                    for node in diagnostic_nodes
                    if node.is_error() or node.is_missing()
                ),
                diagnostic_root,
            )
            diagnostics.append(
                CodeGraphDiagnostic(
                    file_path=rel_path,
                    message=(
                        "Tree-sitter recovered from invalid syntax; "
                        "extracted facts may be incomplete"
                    ),
                    severity="warning",
                    code="codegraph.partial_parse",
                    phase="parse",
                    line=_node_line(syntax_error),
                    start_byte=int(syntax_error.start_byte()),
                    end_byte=int(syntax_error.end_byte()),
                    partial_output=True,
                )
            )
        functions = self._collect_functions(
            root,
            source,
            rel_path,
            language,
            root_nodes=root_nodes,
            macro_masks_by_body={
                mask.body_start: mask for mask in parsed.macro_function_masks
            },
        )
        declarations = (
            self._collect_function_declarations(root, source, root_nodes=root_nodes)
            if language == "cpp"
            else []
        )
        function_ids = {function.node.unique_name for function in functions}
        global_constructs, global_scopes = self._collect_globals(
            root,
            source,
            rel_path,
            function_ids=function_ids,
            root_nodes=root_nodes,
        )
        public_declarations = self._collect_public_function_declarations(
            root,
            source,
            rel_path,
            root_nodes=root_nodes,
        )
        value_declarations = self._collect_namespace_value_declarations(
            source,
            rel_path,
            root_nodes,
        )
        return ParsedFileGraph(
            language=language,
            functions=functions,
            declarations=declarations,
            globals=global_constructs,
            global_scopes=global_scopes,
            value_declarations=value_declarations,
            public_declarations=public_declarations,
            macro_function_definitions=parsed.macro_function_definitions,
            diagnostics=diagnostics,
        )

    def _collect_functions(
        self,
        root: Any,
        source: bytes,
        rel_path: str,
        language: str = "c",
        *,
        root_nodes: tuple[Any, ...] | None = None,
        macro_masks_by_body: dict[int, _MacroFunctionMask] | None = None,
    ) -> list[ParsedFunction]:
        functions: list[ParsedFunction] = []
        seen: set[str] = set()

        nodes = root_nodes or tuple(self._iter_nodes(root))
        for node in nodes:
            if _node_kind(node) not in {"function_definition", "method_definition"}:
                continue
            declarator = _node_child_by_field_name(node, "declarator")
            body = _node_child_by_field_name(node, "body")
            if _has_parse_error_between_declarator_and_body(node, declarator, body):
                continue
            syntax: CFamilyFunctionSyntax | None
            syntax = self._function_syntax(node, source)
            if syntax is None:
                continue
            if language == "c":
                name = _identifier_from_node(declarator or node, source)
                if not name:
                    continue
                syntax = replace(
                    syntax,
                    name=name,
                    qualified_name=name,
                    signature_suffix="",
                    lexical_scope=(),
                )
            unique = (
                f"{rel_path}::{syntax.qualified_name}{syntax.signature_suffix}"
                if language == "cpp"
                else f"{rel_path}::{syntax.name}"
            )
            if unique in seen:
                continue
            seen.add(unique)
            scope_nodes = tuple(self._iter_nodes(node))
            call_sites = tuple(
                self._collect_calls_in_scope(
                    node,
                    source,
                    exclude_symbols=CONTROL_CALLS,
                    include_constructors=language == "cpp",
                    legacy_identifiers=language == "c",
                    scope_nodes=scope_nodes,
                )
            )
            references, value_bindings = self._collect_function_references(
                node,
                source,
                scope_nodes,
            )
            has_internal_linkage = self._has_internal_linkage(node, source)
            is_public_entrypoint = self._is_public_function_definition(
                node,
                source,
                rel_path,
                has_internal_linkage=has_internal_linkage,
            )
            function_node = FunctionNode(
                unique,
                rel_path,
                syntax.name,
                _node_line(node),
                language=language,
                calls=list(dict.fromkeys(call.symbol for call in call_sites)),
                references=list(references),
                end_line=_node_end_line(node),
                start_byte=int(node.start_byte()),
                end_byte=int(node.end_byte()),
                is_public_entrypoint=is_public_entrypoint,
                entrypoint_reason=(
                    "non-static function definition" if is_public_entrypoint else ""
                ),
                has_internal_linkage=has_internal_linkage,
                parameter_count=(
                    syntax.maximum_argument_count
                    if syntax.maximum_argument_count is not None
                    else syntax.minimum_argument_count
                ),
                parameters=syntax.parameters,
                lock_events=self._collect_lock_events(
                    node,
                    source,
                    scope_nodes,
                ),
                assignments=self._collect_value_assignments(
                    node,
                    source,
                    scope_nodes,
                ),
                loops=self._collect_loop_structures(
                    node,
                    source,
                    scope_nodes,
                ),
                returns=self._collect_return_sites(
                    node,
                    source,
                    scope_nodes,
                ),
            )
            noreturn_marker = _noreturn_marker(node, source)
            if noreturn_marker:
                function_node.set_tag(
                    "control.noreturn",
                    value=noreturn_marker,
                    reason=(
                        "function declaration contains "
                        f"{noreturn_marker} at line {_node_line(node)}"
                    ),
                )
            functions.append(
                ParsedFunction(
                    node=function_node,
                    syntax=syntax,
                    calls=call_sites,
                    value_bindings=value_bindings,
                    macro_function_mask=(
                        None
                        if body is None or macro_masks_by_body is None
                        else macro_masks_by_body.get(int(body.start_byte()))
                    ),
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
        *,
        root_nodes: tuple[Any, ...] | None = None,
    ) -> list[CFamilyFunctionSyntax]:
        declarations: list[CFamilyFunctionSyntax] = []
        for node in root_nodes or self._iter_nodes(root):
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
        scope_nodes: tuple[Any, ...] | None = None,
    ) -> list[LockEvent]:
        events: list[LockEvent] = []
        for call in scope_nodes or self._iter_nodes(scope_node):
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

    def _collect_function_references(
        self,
        function_node: Any,
        source: bytes,
        scope_nodes: tuple[Any, ...],
    ) -> tuple[tuple[SymbolReference, ...], tuple[ValueBinding, ...]]:
        bindings: list[ValueBinding] = []
        function_parameters = None
        root_declarator = _node_child_by_field_name(function_node, "declarator")
        declared_name = _declarator_name_node(root_declarator)
        function_declarator = (
            declared_name.parent() if declared_name is not None else None
        )
        while (
            function_declarator is not None and function_declarator is not function_node
        ):
            if _node_kind(function_declarator) == "function_declarator":
                function_parameters = _node_child_by_field_name(
                    function_declarator,
                    "parameters",
                )
                break
            function_declarator = function_declarator.parent()
        references = [
            reference
            for node in scope_nodes
            if _node_kind(node) == "pointer_expression"
            for reference in _function_value_references(
                node,
                source,
                allow_bare=False,
            )
        ]

        for node in scope_nodes:
            node_kind = _node_kind(node)
            if node_kind == "lambda_capture_initializer":
                name_node = _node_child_by_field_name(node, "left")
                if _node_kind(name_node) != "identifier":
                    continue
                binding_targets = _function_value_references(
                    _node_child_by_field_name(node, "right"),
                    source,
                    allow_bare=True,
                )
                references.extend(binding_targets)
                scope = _binding_scope(node, function_node)
                scope = _node_child_by_field_name(scope, "body") or scope
                bindings.append(
                    ValueBinding(
                        name=_node_text(name_node, source).strip(),
                        declaration_byte=int(name_node.start_byte()),
                        scope_start_byte=int(scope.start_byte()),
                        scope_end_byte=int(scope.end_byte()),
                        targets=list(binding_targets) if binding_targets else None,
                    )
                )
                continue
            if node_kind in {
                "declaration",
                "for_range_loop",
                "init_declarator",
                "optional_parameter_declaration",
                "parameter_declaration",
            }:
                is_parameter = node_kind in {
                    "optional_parameter_declaration",
                    "parameter_declaration",
                }
                parameter_list = node.parent() if is_parameter else None
                owns_function_parameter = (
                    is_parameter
                    and function_parameters is not None
                    and parameter_list is not None
                    and int(parameter_list.start_byte())
                    == int(function_parameters.start_byte())
                    and int(parameter_list.end_byte())
                    == int(function_parameters.end_byte())
                )
                owns_catch_parameter = (
                    is_parameter
                    and parameter_list is not None
                    and _node_kind(parameter_list.parent()) == "catch_clause"
                )
                owns_lambda_parameter = (
                    is_parameter
                    and parameter_list is not None
                    and _node_kind(parameter_list.parent()) == "lambda_declarator"
                )
                if is_parameter and (
                    not owns_function_parameter
                    and not owns_catch_parameter
                    and not owns_lambda_parameter
                ):
                    continue
                if node_kind == "init_declarator" and _node_kind(node.parent()) == (
                    "declaration"
                ):
                    continue
                for declaration_node in _declaration_declarators(node):
                    declarator = (
                        _node_child_by_field_name(declaration_node, "declarator")
                        if _node_kind(declaration_node) == "init_declarator"
                        else declaration_node
                    )
                    declaration_kind = _value_declaration_kind(
                        declarator,
                        is_parameter=is_parameter,
                    )
                    if declaration_kind in {"function", "unnamed"}:
                        continue
                    is_pointer_binding = declaration_kind == "function_pointer"
                    value_owner = (
                        declaration_node
                        if _node_kind(declaration_node) == "init_declarator"
                        else node
                    )
                    value = _node_child_by_field_name(
                        value_owner,
                        "value",
                    ) or _node_child_by_field_name(value_owner, "default_value")
                    binding_targets = (
                        _function_value_references(
                            value,
                            source,
                            allow_bare=True,
                        )
                        if is_pointer_binding
                        else ()
                    )
                    references.extend(binding_targets)
                    name_node = _declarator_name_node(declarator)
                    if name_node is None:
                        continue
                    scope = _binding_scope(declaration_node, function_node)
                    bindings.append(
                        ValueBinding(
                            name=_node_text(name_node, source).strip(),
                            declaration_byte=int(name_node.start_byte()),
                            scope_start_byte=int(scope.start_byte()),
                            scope_end_byte=int(scope.end_byte()),
                            targets=(
                                list(binding_targets) if is_pointer_binding else None
                            ),
                        )
                    )
                continue
            if node_kind == "assignment_expression":
                operator = _node_child_by_field_name(node, "operator")
                if _node_text(operator, source).strip() != "=":
                    continue
                left = _node_child_by_field_name(node, "left")
                if _node_kind(left) != "identifier":
                    continue
                binding = _visible_value_binding(
                    tuple(bindings),
                    name=_node_text(left, source).strip(),
                    at_byte=int(node.start_byte()),
                )
                is_pointer_binding = binding is not None and binding.targets is not None
                binding_targets = _function_value_references(
                    _node_child_by_field_name(node, "right"),
                    source,
                    allow_bare=is_pointer_binding,
                )
                if not binding_targets:
                    continue
                if binding is not None and binding.targets is not None:
                    binding.targets.extend(binding_targets)
                references.extend(binding_targets)

        unique_references = {
            (reference.start_byte, reference.end_byte, reference.symbol): reference
            for reference in references
        }
        return (
            tuple(unique_references[key] for key in sorted(unique_references)),
            tuple(bindings),
        )

    def _collect_namespace_value_declarations(
        self,
        source: bytes,
        rel_path: str,
        root_nodes: tuple[Any, ...],
    ) -> dict[tuple[str, str], list[int]]:
        declarations: dict[tuple[str, str], list[int]] = {}
        local_scope_kinds = {
            "class_specifier",
            "compound_statement",
            "function_definition",
            "method_definition",
            "struct_specifier",
            "union_specifier",
        }
        for node in root_nodes:
            if _node_kind(node) != "declaration":
                continue
            parent = node.parent()
            while parent is not None and _node_kind(parent) not in local_scope_kinds:
                parent = parent.parent()
            if parent is not None:
                continue
            lexical_scope = _lexical_scope(node, source)
            for declaration_node in _declaration_declarators(node):
                declarator = (
                    _node_child_by_field_name(declaration_node, "declarator")
                    if _node_kind(declaration_node) == "init_declarator"
                    else declaration_node
                )
                if _value_declaration_kind(declarator, is_parameter=False) in {
                    "function",
                    "unnamed",
                }:
                    continue
                name_node = _declarator_name_node(declarator)
                if name_node is None:
                    continue
                name = _node_text(name_node, source).strip()
                qualified_name = "::".join((*lexical_scope, name))
                visible_names = [qualified_name]
                if ANONYMOUS_NAMESPACE_SCOPE in lexical_scope:
                    visible_names.append(
                        "::".join(
                            part
                            for part in (*lexical_scope, name)
                            if part != ANONYMOUS_NAMESPACE_SCOPE
                        )
                    )
                for visible_name in visible_names:
                    declarations.setdefault((rel_path, visible_name), []).append(
                        int(name_node.start_byte())
                    )
        return declarations

    def _collect_globals(
        self,
        root,
        source: bytes,
        rel_path: str,
        *,
        function_ids: set[str] | None = None,
        root_nodes: tuple[Any, ...] | None = None,
    ) -> tuple[
        list[GlobalConstruct],
        dict[str, tuple[str, ...]],
    ]:
        globals_: list[GlobalConstruct] = []
        global_scopes: dict[str, tuple[str, ...]] = {}
        seen: set[str] = set()

        for node in root_nodes or self._iter_nodes(root):
            if _node_kind(node) != "init_declarator":
                continue
            parent = node.parent()
            while parent is not None and _node_kind(parent) not in {
                "class_specifier",
                "compound_statement",
                "function_definition",
                "method_definition",
                "struct_specifier",
                "union_specifier",
                "ERROR",
            }:
                parent = parent.parent()
            if parent is not None:
                continue
            references = self._global_symbol_references(node, source)
            refs = list(
                dict.fromkeys(
                    reference.symbol.rpartition("::")[2]
                    for reference in references
                    if reference.symbol
                )
            )
            if not refs:
                continue
            name = self._global_name(node, source) or f"global_{_node_line(node)}"
            lexical_scope = _lexical_scope(node, source)
            qualified_name = "::".join((*lexical_scope, name))
            unique = f"{rel_path}::{qualified_name}"
            if function_ids is not None and unique in function_ids:
                continue
            if unique not in seen:
                seen.add(unique)
                global_scopes[unique] = lexical_scope
                globals_.append(
                    GlobalConstruct(
                        unique,
                        rel_path,
                        name,
                        _node_line(node),
                        initializer=_node_text(node, source)[:2000],
                        referenced_functions=refs,
                        references=references,
                    )
                )
        return globals_, global_scopes

    def _collect_public_function_declarations(
        self,
        root,
        source: bytes,
        rel_path: str,
        *,
        root_nodes: tuple[Any, ...] | None = None,
    ) -> dict[str, list[str]]:
        if not self._has_file_role(rel_path, "header"):
            return {}
        declarations: dict[str, list[str]] = {}
        for node in root_nodes or self._iter_nodes(root):
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

    def _global_symbol_references(
        self,
        node: Any,
        source: bytes,
    ) -> list[SymbolReference]:
        value = _node_child_by_field_name(node, "value")
        if value is None:
            return []
        references: list[SymbolReference] = []
        covered_ranges: list[tuple[int, int]] = []
        for candidate in self._iter_nodes(value):
            start_byte = int(candidate.start_byte())
            end_byte = int(candidate.end_byte())
            if any(
                start_byte >= covered_start and end_byte <= covered_end
                for covered_start, covered_end in covered_ranges
            ):
                continue
            reference = _symbol_reference_from_expression(
                candidate,
                source,
                allow_bare=True,
            )
            if reference is None:
                continue
            references.append(reference)
            covered_ranges.append((start_byte, end_byte))
        return references

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


def _noreturn_marker(node: Any, source: bytes) -> str:
    stack = list(reversed(_node_children(node)))
    while stack:
        current = stack.pop()
        kind = _node_kind(current)
        if kind in {"compound_statement", "parameter_list"}:
            continue
        if kind == "type_qualifier" and _node_text(current, source) == "_Noreturn":
            return "_Noreturn"
        if kind == "attribute_specifier" and _gnu_noreturn_attribute(current, source):
            return "GNU noreturn attribute"
        if kind == "attribute" and _cpp_noreturn_attribute(current, source):
            return "[[noreturn]]"
        if kind == "ms_declspec_modifier" and _msvc_noreturn_declspec(current, source):
            return "MSVC noreturn declspec"
        stack.extend(reversed(_node_children(current)))
    return ""


def _annotate_macro_function_wrappers(
    functions: list[ParsedFunction],
    definitions: list[_MacroFunctionDefinition],
) -> None:
    definitions_by_name: dict[str, list[_MacroFunctionDefinition]] = {}
    for definition in definitions:
        definitions_by_name.setdefault(definition.name, []).append(definition)

    for function in functions:
        mask = function.macro_function_mask
        if mask is None:
            continue
        matching_definitions = tuple(
            definition
            for definition in definitions_by_name.get(mask.macro_name, ())
            if len(definition.parameters) == mask.argument_count
        )
        if not matching_definitions:
            continue
        referenced_identifiers = tuple(
            dict.fromkeys(
                identifier
                for argument in mask.annotation_arguments
                if all(
                    argument.index in definition.referenced_parameter_indexes
                    for definition in matching_definitions
                )
                for identifier in argument.identifiers
            )
        )
        if not referenced_identifiers:
            continue
        function.node.set_tag(
            "syntax.macro_function_arguments",
            value=", ".join(referenced_identifiers),
            reason=(
                f"{mask.macro_name} definitions reference non-signature wrapper "
                f"argument tokens at line {function.node.line_number}"
            ),
        )


def _annotate_macro_passthrough_calls(
    functions: list[ParsedFunction],
    definitions: list[_MacroFunctionDefinition],
) -> None:
    definitions_by_name: dict[str, list[_MacroFunctionDefinition]] = {}
    for definition in definitions:
        definitions_by_name.setdefault(definition.name, []).append(definition)

    for function in functions:
        calls = list(function.calls)
        wrapper_indexes = sorted(
            range(len(calls)),
            key=lambda index: (
                -(calls[index].end_byte - calls[index].start_byte),
                calls[index].start_byte,
            ),
        )
        for wrapper_index in wrapper_indexes:
            wrapper = calls[wrapper_index]
            lexical_arity = len(wrapper.lexical_argument_spans)
            if not lexical_arity:
                continue
            matching = tuple(
                definition
                for definition in definitions_by_name.get(wrapper.symbol, ())
                if len(definition.parameters) == lexical_arity
            )
            passthrough_indexes = {
                definition.passthrough_parameter_index for definition in matching
            }
            if len(passthrough_indexes) != 1:
                continue
            passthrough_index = next(iter(passthrough_indexes))
            if passthrough_index is None:
                continue
            wrapper = replace(
                wrapper,
                argument_count=lexical_arity,
            )
            calls[wrapper_index] = wrapper
            if wrapper.result is None:
                continue
            argument_span = wrapper.lexical_argument_spans[passthrough_index]
            rooted_calls = [
                index
                for index, candidate in enumerate(calls)
                if index != wrapper_index
                and (candidate.start_byte, candidate.end_byte) == argument_span
            ]
            if len(rooted_calls) != 1:
                continue
            nested_index = rooted_calls[0]
            nested = calls[nested_index]
            if nested.result not in {None, wrapper.result}:
                continue
            calls[nested_index] = replace(nested, result=wrapper.result)
        function.calls = tuple(calls)


def _gnu_noreturn_attribute(node: Any, source: bytes) -> bool:
    arguments = next(
        (
            child
            for child in _node_children(node)
            if _node_kind(child) == "argument_list"
        ),
        None,
    )
    return arguments is not None and any(
        _node_kind(child) == "identifier"
        and _node_text(child, source) in {"noreturn", "__noreturn__"}
        for child in _node_children(arguments)
    )


def _cpp_noreturn_attribute(node: Any, source: bytes) -> bool:
    names = [
        _node_text(child, source)
        for child in _node_children(node)
        if _node_kind(child) == "identifier"
    ]
    return bool(names) and names[-1] == "noreturn"


def _msvc_noreturn_declspec(node: Any, source: bytes) -> bool:
    return any(
        _node_kind(child) == "identifier" and _node_text(child, source) == "noreturn"
        for child in _node_children(node)
    )


def _declaration_declarators(node: Any) -> tuple[Any, ...]:
    first_declarator = _node_child_by_field_name(node, "declarator")
    if first_declarator is None:
        return ()
    if _node_kind(node) != "declaration":
        return (first_declarator,)

    declarators: list[Any] = []
    expecting_declarator = False
    first_start_byte = int(first_declarator.start_byte())
    for child in _node_children(node):
        child_kind = _node_kind(child)
        if int(child.start_byte()) == first_start_byte:
            declarators.append(child)
            continue
        if not declarators:
            continue
        if child_kind == ",":
            expecting_declarator = True
            continue
        if child_kind == "comment":
            continue
        if expecting_declarator:
            declarators.append(child)
            expecting_declarator = False
    return tuple(declarators)


def _binding_scope(candidate: Any, function_node: Any) -> Any:
    current = candidate
    while current is not None and current is not function_node:
        if _node_kind(current) in {
            "catch_clause",
            "compound_statement",
            "for_range_loop",
            "for_statement",
            "if_statement",
            "lambda_expression",
            "switch_statement",
            "while_statement",
        }:
            return current
        current = current.parent()
    return _node_child_by_field_name(function_node, "body") or function_node


def _value_declaration_kind(
    declarator: Any,
    *,
    is_parameter: bool,
) -> ValueDeclarationKind:
    name_node = _declarator_name_node(declarator)
    if name_node is None:
        return "unnamed"
    current = name_node.parent()
    pointer_depth = 0
    while current is not None:
        current_kind = _node_kind(current)
        if current_kind == "pointer_declarator":
            pointer_depth += 1
        elif current_kind == "function_declarator":
            if pointer_depth == 1 or (is_parameter and pointer_depth == 0):
                return "function_pointer"
            return "function" if pointer_depth == 0 else "value"
        elif current_kind in {
            "declaration",
            "function_definition",
            "optional_parameter_declaration",
            "parameter_declaration",
        }:
            return "value"
        current = current.parent()
    return "value"


def _function_value_references(
    expression: Any,
    source: bytes,
    *,
    allow_bare: bool,
) -> tuple[SymbolReference, ...]:
    reference = _symbol_reference_from_expression(
        expression,
        source,
        allow_bare=allow_bare,
    )
    if reference is not None:
        return (reference,)
    if expression is None or _node_kind(expression) != "conditional_expression":
        return ()
    branches = (
        _node_child_by_field_name(expression, "consequence"),
        _node_child_by_field_name(expression, "alternative"),
    )
    return tuple(
        reference
        for branch in branches
        for reference in _function_value_references(
            branch,
            source,
            allow_bare=allow_bare,
        )
    )


def _symbol_reference_from_expression(
    expression: Any,
    source: bytes,
    *,
    allow_bare: bool,
) -> SymbolReference | None:
    if expression is None:
        return None
    current = expression
    while current is not None and _node_kind(current) == "parenthesized_expression":
        values = _expression_children(current)
        current = values[0] if len(values) == 1 else None
    if current is None:
        return None
    addressed = False
    if _node_kind(current) == "pointer_expression":
        operator = _node_child_by_field_name(current, "operator")
        if _node_text(operator, source).strip() != "&":
            return None
        addressed = True
        current = _node_child_by_field_name(current, "argument")
    if current is None:
        return None
    if not allow_bare and not addressed:
        return None
    if _node_kind(current) not in {"identifier", "qualified_identifier"}:
        return None
    symbol = _normalized_syntax(_node_text(current, source))
    if not symbol:
        return None
    return SymbolReference(
        symbol=symbol,
        line=_node_line(current),
        start_byte=int(current.start_byte()),
        end_byte=int(current.end_byte()),
    )


def _first_argument(call_node: Any) -> Any | None:
    arguments = _node_child_by_field_name(call_node, "arguments")
    if arguments is None:
        return None
    for child in _node_children(arguments):
        if _node_kind(child) not in {"(", ")", ",", "comment"}:
            return child
    return None


def _has_parse_error_between_declarator_and_body(
    function_node: Any,
    declarator: Any,
    body: Any,
) -> bool:
    if declarator is None or body is None:
        return False
    declarator_end = int(declarator.end_byte())
    body_start = int(body.start_byte())
    return any(
        child.is_error()
        and declarator_end <= int(child.start_byte())
        and int(child.end_byte()) <= body_start
        for child in _node_children(function_node)
    )
