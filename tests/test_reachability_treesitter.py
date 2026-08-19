# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from metis.engine.codegraph import CallSite
from metis.engine.codegraph import CodeExpression
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import CodeGraphResult
from metis.engine.codegraph import ControlCondition
from metis.engine.codegraph import FunctionNode
from metis.engine.codegraph import FunctionParameter
from metis.engine.codegraph import GlobalConstruct
from metis.engine.codegraph import SymbolReference
from metis.engine.codegraph import ValueAssignment
from metis.engine.nodes.codegraph import CodeGraphConfiguration
from metis.engine.nodes.codegraph import CodeGraphSemanticsCatalog
from metis.engine.nodes.codegraph import CodeGraphService
from metis.engine.nodes.reachability import VulnerabilityFinding
from metis.engine.nodes.reachability.finding_paths import FindingPathAnnotator
from metis.engine.nodes.reachability.graph_utils import _copy_graph_nodes
from metis.engine.nodes.reachability.graph_utils import graph_fingerprint
from metis.engine.nodes.reachability.options import ReachabilityReviewOptions
from metis.engine.nodes.reachability.service import ReachabilityService
from metis.engine.nodes.reachability.state import ParameterSubject
from metis.engine.nodes.reachability.state import augment_function_contracts
from metis.plugins.c_family.ast import CFamilyAstMixin
from metis.plugins.c_family.codegraph import CFamilyCodeGraphProvider
from metis.plugins.c_family.codegraph import CFamilyTreeSitterExtractor
from metis.plugins.c_family.semantics import CFamilyCodeGraphSemantics
from metis.plugins.base import ConfigBackedLanguagePlugin


class _Point:
    def __init__(self, row, column):
        self.row = row
        self.column = column


class _Node:
    def __init__(
        self,
        node_type,
        *,
        text="",
        line=1,
        children=None,
        fields=None,
        start_byte=0,
        end_byte=0,
    ):
        self._type = node_type
        self.text = text
        self._start_position = _Point(line - 1, 0)
        self._end_position = _Point(line - 1, 0)
        self._start_byte = start_byte
        self._end_byte = end_byte
        self._children = children or []
        self._fields = fields or {}
        self._parent = None
        for child in self._children:
            child._parent = self
        for child in self._fields.values():
            child._parent = self

    def kind(self):
        return self._type

    def start_position(self):
        return self._start_position

    def end_position(self):
        return self._end_position

    def start_byte(self):
        return self._start_byte

    def end_byte(self):
        return self._end_byte

    def child_count(self):
        return len(self._children)

    def child(self, index):
        return self._children[index]

    def child_by_field_name(self, name):
        return self._fields.get(name)

    def parent(self):
        return self._parent


def _codegraph_service(codebase_path, *, files=(), annotation_settings=None):
    plugin = ConfigBackedLanguagePlugin(plugin_config={"plugins": {}}, name="c")
    repository = SimpleNamespace(
        get_code_files=lambda **_kwargs: list(files),
        is_code_file_selected=lambda path, **_kwargs: (
            Path(codebase_path) / path
        ).is_file(),
        get_plugin_for_path=lambda _path: plugin,
        get_codegraph_registration=lambda path: (
            "c_family"
            if str(path).endswith((".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"))
            else None
        ),
        get_language_name_for_path=lambda path: (
            "cpp" if str(path).endswith((".cc", ".cpp", ".cxx", ".hpp")) else "c"
        ),
        has_language_file_role=lambda path, role: (
            role == "header" and str(path).endswith((".h", ".hpp"))
        ),
    )
    service = CodeGraphService(
        SimpleNamespace(codebase_path=codebase_path),
        repository,
        {"c_family": CFamilyCodeGraphProvider},
        annotation_settings=CodeGraphConfiguration.model_validate(
            annotation_settings or {}
        ),
        semantics=CodeGraphSemanticsCatalog(
            providers={"c_family": CFamilyCodeGraphSemantics()},
        ),
    )
    service._provider("c_family")
    return service


def _patch_ids(monkeypatch):
    import metis.plugins.c_family.ast as c_family_ast
    import metis.plugins.c_family.codegraph as c_family

    def fake_identifier(node, _source):
        return getattr(node, "text", "") if node else ""

    monkeypatch.setattr(c_family, "_node_text", lambda node, _source: node.text)
    monkeypatch.setattr(c_family, "_identifier_from_node", fake_identifier)
    monkeypatch.setattr(c_family_ast, "_identifier_from_node", fake_identifier)
    monkeypatch.setattr(c_family_ast, "_node_text", lambda node, _source: node.text)


def _call(name, line=1):
    ident = _Node("identifier", text=name, line=line)
    return _Node("call_expression", line=line, fields={"function": ident})


def _func(name, text, line, *, child=None):
    children = [child] if child else []
    declarator = _Node(
        "function_declarator",
        text=name,
        line=line,
        fields={
            "declarator": _Node("identifier", text=name, line=line),
            "parameters": _Node("parameter_list", text="()", line=line),
        },
    )
    return _Node(
        "function_definition",
        text=text,
        line=line,
        children=children,
        fields={"declarator": declarator},
    )


def _deep_chain(depth, leaf):
    node = leaf
    for idx in range(depth):
        node = _Node(f"wrapper_{idx}", children=[node])
    return node


def _fn(unique, line, *, source=False, sink=False, calls=None):
    file_path, name = unique.rsplit("::", 1)
    return FunctionNode(
        unique,
        file_path,
        name,
        line,
        is_source=source,
        is_sink=sink,
        calls=list(calls or []),
        sink_type="other" if sink else "",
    )


def _graph(*nodes):
    graph = CodeGraph()
    for node in nodes:
        graph.add_node(node)
    graph.resolve_all_calls()
    return graph


def _finding(vtype, function, line, description, root_cause, **kwargs):
    file_path = function.rsplit("::", 1)[0]
    return VulnerabilityFinding(
        f"{vtype}-{line}",
        vtype,
        "high",
        0.95,
        function,
        file_path,
        line,
        function,
        file_path,
        line,
        path=list(kwargs.get("path") or [function]),
        description=description,
        root_cause=root_cause,
        evidence=root_cause,
        analysis_type=kwargs.get("analysis_type", "test"),
        primary_file=file_path,
        primary_function=function,
        primary_line=line,
        canonical_key=kwargs.get("canonical_key", ""),
    )


def test_codegraph_service_uses_installed_parser_runtime(tmp_path):
    source = tmp_path / "main.c"
    source.write_text(
        "void foo(void) {}\nint main(void) { foo(); return 0; }\n",
        encoding="utf-8",
    )
    events = []
    service = _codegraph_service(str(tmp_path), files=(str(source),))
    reference = service.materialize(progress_callback=events.append)
    graph = service.load(reference)
    done = [event for event in events if event["event"] == "codegraph_done"]
    assert done and not done[0]["errors"]
    assert graph.node_count() == 2
    assert graph.get_node("main.c::main").resolved_calls == ["main.c::foo"]


def test_c_family_provider_reports_partial_parse_without_dropping_file(tmp_path):
    source = tmp_path / "partial.c"
    source.write_text("void valid(void) {}\nvoid broken( {\n", encoding="utf-8")
    service = _codegraph_service(str(tmp_path), files=(str(source),))
    provider = service._providers["c_family"]

    with ThreadPoolExecutor(max_workers=1) as executor:
        result = executor.submit(
            provider.build_graph,
            codebase_path=str(tmp_path),
            files=(str(source),),
        ).result()

    assert result.processed_files == (str(source),)
    assert result.failed_files == ()
    assert result.graph.get_node("partial.c::valid") is not None
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "codegraph.partial_parse"
    assert diagnostic.phase == "parse"
    assert diagnostic.severity == "warning"
    assert diagnostic.partial_output is True
    assert diagnostic.line == 2
    assert source.read_bytes()[diagnostic.start_byte : diagnostic.end_byte]


def test_c_codegraph_recovers_generic_macro_wrapped_function_definitions(tmp_path):
    source = tmp_path / "wrapped.c"
    source.write_text(
        "#define FUNCTION_WRAPPER(result, name, parameters, attributes) attributes result name parameters\n"
        "#define DISCARDING_WRAPPER(result, name, parameters, attributes) result name parameters\n"
        "void target(void) {}\n"
        "#if ENABLED\n"
        "FUNCTION_WRAPPER(void, wrapped, (int first, int second), PNG_NORETURN)\n"
        "{\n"
        "  target();\n"
        "}\n"
        "#endif\n"
        "static FUNCTION_WRAPPER(void, hidden, (void), private)\n"
        "{\n"
        "  target();\n"
        "}\n"
        "DISCARDING_WRAPPER(void, returning, (void), PNG_NORETURN)\n"
        "{\n"
        "  target();\n"
        "}\n"
        "FUNCTION_WRAPPER(void, declaration_only, (void), exported);\n"
        "_Noreturn void fatal(void) { target(); }\n"
        "__attribute__((noreturn)) void gnu_fatal(void) { target(); }\n"
        "__attribute__((__noreturn__)) void gnu_fatal_alt(void) { target(); }\n"
        "__declspec(noreturn) void msvc_fatal(void) { target(); }\n"
        '__attribute__((deprecated("noreturn"))) void deprecated_only(void) {}\n'
        "void might_noreturn(void) {}\n"
        "void takes_noreturn(int noreturn) {}\n"
        "void caller(void) { wrapped(1, 2); }\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))
    provider = service._providers["c_family"]

    with ThreadPoolExecutor(max_workers=1) as executor:
        result = executor.submit(
            provider.build_graph,
            codebase_path=str(tmp_path),
            files=(str(source),),
        ).result()

    wrapped = result.graph.get_node("wrapped.c::wrapped")
    assert wrapped is not None
    assert (wrapped.line_number, wrapped.end_line) == (5, 8)
    assert wrapped.parameter_count == 2
    assert wrapped.calls == ["target"]
    assert wrapped.resolved_calls == ["wrapped.c::target"]
    assert result.graph.get_node("wrapped.c::caller").resolved_calls == [
        "wrapped.c::wrapped"
    ]
    hidden = result.graph.get_node("wrapped.c::hidden")
    assert hidden is not None
    assert hidden.parameter_count == 0
    assert hidden.has_internal_linkage is True
    assert hidden.is_public_entrypoint is False
    assert wrapped.tags["syntax.macro_function_arguments"].value == "PNG_NORETURN"
    assert (
        wrapped.tags["syntax.macro_function_arguments"].reason
        == "FUNCTION_WRAPPER definitions reference non-signature wrapper argument tokens at line 5"
    )
    assert result.graph.get_node("wrapped.c::returning").tags == {}
    assert (
        result.graph.get_node("wrapped.c::fatal").tags["control.noreturn"].value
        == "_Noreturn"
    )
    assert (
        result.graph.get_node("wrapped.c::gnu_fatal").tags["control.noreturn"].value
        == "GNU noreturn attribute"
    )
    assert (
        result.graph.get_node("wrapped.c::gnu_fatal_alt").tags["control.noreturn"].value
        == "GNU noreturn attribute"
    )
    assert (
        result.graph.get_node("wrapped.c::msvc_fatal").tags["control.noreturn"].value
        == "MSVC noreturn declspec"
    )
    assert result.graph.get_node("wrapped.c::deprecated_only").tags == {}
    assert result.graph.get_node("wrapped.c::might_noreturn").tags == {}
    assert result.graph.get_node("wrapped.c::takes_noreturn").tags == {}
    assert result.graph.get_node("wrapped.c::declaration_only") is None
    assert all(
        "FUNCTION_WRAPPER" not in node.calls for node in result.graph.nodes.values()
    )
    assert result.processed_files == (str(source),)
    assert result.failed_files == ()
    assert [diagnostic.code for diagnostic in result.diagnostics] == [
        "codegraph.partial_parse"
    ]


def test_c_codegraph_resolves_wrapper_annotations_across_files(tmp_path):
    source = tmp_path / "a_use.c"
    source.write_text(
        "CROSS_FILE_WRAPPER(void, fatal, (void), PROJECT_NORETURN)\n{\n}\n",
        encoding="utf-8",
    )
    definitions = tmp_path / "z_definitions.h"
    definitions.write_text(
        "#define CROSS_FILE_WRAPPER(result, name, parameters, attributes) "
        "attributes result name parameters\n",
        encoding="utf-8",
    )
    service = _codegraph_service(
        str(tmp_path),
        files=(str(source), str(definitions)),
    )

    graph = service.load(service.materialize())

    fatal = graph.get_node("a_use.c::fatal")
    assert fatal is not None
    assert fatal.tags["syntax.macro_function_arguments"].value == "PROJECT_NORETURN"
    assert "control.noreturn" not in fatal.tags


def test_cpp_codegraph_reads_exact_noreturn_attribute_names(tmp_path):
    source = tmp_path / "attributes.cpp"
    source.write_text(
        "[[noreturn]] void fatal() {}\n"
        "[[vendor::noreturn]] void vendor_fatal() {}\n"
        '[[deprecated("noreturn")]] void deprecated_only() {}\n'
        "void named_noreturn(int noreturn) {}\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    assert (
        graph.nodes["attributes.cpp::fatal()"].tags["control.noreturn"].value
        == "[[noreturn]]"
    )
    assert (
        graph.nodes["attributes.cpp::vendor_fatal()"].tags["control.noreturn"].value
        == "[[noreturn]]"
    )
    assert graph.nodes["attributes.cpp::deprecated_only()"].tags == {}
    assert graph.nodes["attributes.cpp::named_noreturn(int)"].tags == {}


def test_cpp_codegraph_normalizes_parameter_declarators(tmp_path):
    source = tmp_path / "parameters.cpp"
    source.write_text(
        "template<typename T> struct wrapper {};\n"
        "struct state {};\n"
        "void sample(state *state_ptr, wrapper<int*> value, int *&out) {}\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    assert graph.nodes[
        "parameters.cpp::sample(state*,wrapper<int*>,int*&)"
    ].parameters == (
        FunctionParameter("state_ptr", "state*"),
        FunctionParameter("value", "wrapper<int*>"),
        FunctionParameter("out", "int*&"),
    )


def test_c_codegraph_preserves_value_control_and_field_evidence(tmp_path):
    source = tmp_path / "semantic.c"
    source.write_text(
        "typedef unsigned char *byte_ptr;\n"
        "struct state { unsigned char *value; };\n"
        "void getter(struct state *state, unsigned char **out) {\n"
        "  if (out != 0) *out = state->value;\n"
        "}\n"
        "void transformed_getter(struct state *state, unsigned char **out) {\n"
        "  *out = decode(state->value);\n"
        "}\n"
        "void parenthesized_getter(struct state *state, unsigned char **out) {\n"
        "  *out = (state->value);\n"
        "}\n"
        "void alias_getter(struct state *state, byte_ptr *out) {\n"
        "  *out = state->value;\n"
        "}\n"
        "void alias_setter(struct state *state, byte_ptr input) {\n"
        "  release(state, state->value); consume(input);\n"
        "}\n"
        "void setter(struct state *state, unsigned char *value, unsigned size) {\n"
        "  if (value != 0) {\n"
        "    release(state, state->value);\n"
        "    state->value = allocate(size);\n"
        "    copy(state->value, value, size);\n"
        "  }\n"
        "}\n"
        "void stuck(unsigned skip) {\n"
        "  while (skip > 0) { unsigned len = skip; read_bytes(len); }\n"
        "}\n"
        "void progressing(unsigned skip) {\n"
        "  while (skip > 0) { --skip; }\n"
        "}\n"
        "void pointer_init(unsigned size) {\n"
        "  unsigned char *buffer = allocate(size);\n"
        "  if (is_ready(buffer)) copy(buffer, buffer, size);\n"
        "}\n"
        "void unevaluated(int *pointer) {\n"
        "  consume(sizeof *pointer);\n"
        "}\n"
        "void loop_conditions(int flag) {\n"
        "  do { read_bytes(1); } while (flag);\n"
        "  for (read_bytes(2); flag; read_bytes(3)) read_bytes(4);\n"
        "}\n"
        "void field_loop(struct state *state) {\n"
        "  while (state->value != 0) { state->value = 0; consume(&state->value); }\n"
        "}\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    getter = graph.nodes["semantic.c::getter"]
    assert len(getter.assignments) == 1
    assignment = getter.assignments[0]
    assert assignment.target.text == "*out"
    assert assignment.target.identifiers == ("out",)
    assert assignment.value.text == "state->value"
    assert assignment.value.identifiers == ("state",)
    assert assignment.value.field_paths == ("state.value",)
    assert assignment.value.direct_field_path == "state.value"
    assert assignment.operator == "="
    assert [(item.expression.text, item.truth) for item in assignment.conditions] == [
        ("out != 0", True)
    ]
    assert (
        source.read_bytes()[assignment.start_byte : assignment.end_byte]
        == b"*out = state->value"
    )

    transformed = graph.nodes["semantic.c::transformed_getter"]
    assert transformed.assignments[0].value.field_paths == ("state.value",)
    assert transformed.assignments[0].value.direct_field_path == ""

    parenthesized = graph.nodes["semantic.c::parenthesized_getter"]
    assert parenthesized.assignments[0].value.direct_field_path == "state.value"

    alias_getter = graph.nodes["semantic.c::alias_getter"]
    alias_setter = graph.nodes["semantic.c::alias_setter"]
    assert alias_getter.parameters[1] == FunctionParameter("out", "byte_ptr*")
    assert alias_setter.parameters[1] == FunctionParameter("input", "byte_ptr")

    setter = graph.nodes["semantic.c::setter"]
    release = next(call for call in setter.call_sites if call.symbol == "release")
    copy = next(call for call in setter.call_sites if call.symbol == "copy")
    assert [argument.text for argument in release.arguments] == [
        "state",
        "state->value",
    ]
    assert release.arguments[1].field_paths == ("state.value",)
    assert [(item.expression.text, item.truth) for item in release.conditions] == [
        ("value != 0", True)
    ]
    assert [argument.text for argument in copy.arguments] == [
        "state->value",
        "value",
        "size",
    ]

    stuck = graph.nodes["semantic.c::stuck"]
    progressing = graph.nodes["semantic.c::progressing"]
    assert len(stuck.loops) == 1
    assert stuck.loops[0].written_identifiers == ("len",)
    assert stuck.loops[0].addressed_identifiers == ()
    assert stuck.loops[0].condition is not None
    assert stuck.loops[0].condition.text == "skip>0"
    assert stuck.loops[0].condition.identifiers == ("skip",)
    assert progressing.loops[0].written_identifiers == ("skip",)

    pointer_init = graph.nodes["semantic.c::pointer_init"]
    assert pointer_init.parameters == (FunctionParameter("size", "unsigned"),)
    pointer_assignment = pointer_init.assignments[0]
    allocate = next(
        call for call in pointer_init.call_sites if call.symbol == "allocate"
    )
    is_ready = next(
        call for call in pointer_init.call_sites if call.symbol == "is_ready"
    )
    guarded_copy = next(
        call for call in pointer_init.call_sites if call.symbol == "copy"
    )
    assert pointer_assignment.target.text == "buffer"
    assert allocate.result is not None
    assert allocate.result.text == "buffer"
    assert is_ready.conditions == ()
    assert [item.expression.text for item in guarded_copy.conditions] == [
        "is_ready(buffer)"
    ]

    unevaluated = graph.nodes["semantic.c::unevaluated"]
    assert unevaluated.call_sites[0].arguments[0].text == "sizeof*pointer"
    assert unevaluated.call_sites[0].arguments[0].identifiers == ()

    loop_conditions = graph.nodes["semantic.c::loop_conditions"]
    assert all(call.conditions == () for call in loop_conditions.call_sites)

    field_loop = graph.nodes["semantic.c::field_loop"]
    assert field_loop.loops[0].condition is not None
    assert field_loop.loops[0].condition.identifiers == ("state",)
    assert field_loop.loops[0].condition.field_paths == ("state.value",)
    assert field_loop.loops[0].written_identifiers == ()
    assert field_loop.loops[0].addressed_identifiers == ()


def test_c_codegraph_derives_conditional_nonnull_return_contracts(
    tmp_path: Path,
) -> None:
    source = tmp_path / "contracts.c"
    source.write_text(
        "_Noreturn void fatal(void) { for (;;) {} }\n"
        "void *raw(void *context);\n"
        "void *checked(void *context) {\n"
        "  void *result;\n"
        "  if (context == NULL) return NULL;\n"
        "  result = raw(context);\n"
        "  if (result == NULL) fatal();\n"
        "  return result;\n"
        "}\n"
        "void *forwarded(void *context) { return checked(context); }\n"
        "void observe(void);\n"
        "void *observed(void *context) {\n"
        "  void *result = checked(context);\n"
        "  observe();\n"
        "  return result;\n"
        "}\n"
        "void mutate(void **result);\n"
        "void *conditional(void *context, int ready) {\n"
        "  void *result;\n"
        "  if (ready) result = checked(context);\n"
        "  return result;\n"
        "}\n"
        "void *mutated(void *context) {\n"
        "  void *result = checked(context);\n"
        "  mutate(&result);\n"
        "  return result;\n"
        "}\n"
        "void *mutated_after_check(void *context) {\n"
        "  void *result = raw(context);\n"
        "  if (result == NULL) fatal();\n"
        "  mutate(&result);\n"
        "  return result;\n"
        "}\n"
        "\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))
    graph = service.load(service.materialize())

    checked = graph.nodes["contracts.c::checked"]
    assert checked.returns[0].returns_null is True
    assert checked.returns[-1].value is not None
    assert checked.returns[-1].value.direct_identifier == "result"
    assert checked.returns[0].conditions[0].null_condition is not None
    assert (
        checked.returns[0].conditions[0].null_condition.when_false[0].is_null is False
    )

    contracts = augment_function_contracts(graph)
    checked_transfer = contracts[checked.unique_name].normal_return_transfers
    assert len(checked_transfer) == 1
    assert checked_transfer[0].requirements[0].atom.subject == ParameterSubject(
        checked.unique_name,
        0,
    )
    forwarded = contracts["contracts.c::forwarded"].normal_return_transfers
    assert len(forwarded) == 1
    assert forwarded[0].requirements[0].atom.subject == ParameterSubject(
        "contracts.c::forwarded",
        0,
    )
    observed = contracts["contracts.c::observed"].normal_return_transfers
    assert len(observed) == 1
    assert observed[0].requirements[0].atom.subject == ParameterSubject(
        "contracts.c::observed",
        0,
    )
    assert not contracts["contracts.c::conditional"].normal_return_transfers
    assert not contracts["contracts.c::mutated"].normal_return_transfers
    assert not contracts["contracts.c::mutated_after_check"].normal_return_transfers


def test_semantic_relationships_affect_cache_keys_and_scoped_copies():
    target = _fn("src/target.c::target", 2)
    caller = _fn("src/caller.c::caller", 1, calls=["target"])
    caller.call_sites = [
        CallSite(
            "target",
            1,
            1,
            target_ids=(target.unique_name,),
            arguments=(CodeExpression("value", 1, 7, 12, identifiers=("value",)),),
        )
    ]
    caller.assignments = [
        ValueAssignment(
            target=CodeExpression("out", 1, 1, 4, identifiers=("out",)),
            value=CodeExpression("value", 1, 7, 12, identifiers=("value",)),
            operator="=",
            line=1,
            start_byte=1,
            end_byte=12,
            conditions=(
                ControlCondition(
                    CodeExpression("ready", 1, 13, 18, identifiers=("ready",)),
                    True,
                ),
            ),
        )
    ]
    graph = _graph(caller, target)
    without_semantics = graph.copy()
    without_semantics.nodes[caller.unique_name].assignments = []
    without_semantics.nodes[caller.unique_name].call_sites[0] = CallSite(
        "target",
        1,
        1,
        target_ids=(target.unique_name,),
    )

    focus = _copy_graph_nodes(graph, {caller.unique_name})

    assert graph_fingerprint(graph) != graph_fingerprint(without_semantics)
    assert focus.nodes[caller.unique_name].assignments == caller.assignments
    focus.nodes[caller.unique_name].assignments.clear()
    assert len(graph.nodes[caller.unique_name].assignments) == 1


def test_c_macro_recovery_does_not_turn_block_macros_into_functions(tmp_path):
    source = tmp_path / "block_macro.c"
    source.write_text(
        "#define FOREACH(item, collection) for (;;)\n"
        "void target(void) {}\n"
        "FOREACH(item, (list))\n"
        "{\n"
        "  target();\n"
        "}\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    assert graph.get_node("block_macro.c::target") is not None
    assert graph.get_node("block_macro.c::item") is None


def test_c_macro_recovery_separates_preprocessor_alternative_functions(tmp_path):
    source = tmp_path / "alternatives.c"
    source.write_text(
        "#define FUNCTION_WRAPPER(result, name, parameters, attributes) result name parameters\n"
        "void target(void) {}\n"
        "void release(void)\n"
        "{\n"
        "#ifdef CUSTOM_RELEASE\n"
        "  target();\n"
        "}\n"
        "FUNCTION_WRAPPER(void, release_default, (void), exported)\n"
        "{\n"
        "#endif\n"
        "  target();\n"
        "}\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    release = graph.get_node("alternatives.c::release")
    release_default = graph.get_node("alternatives.c::release_default")
    assert release is not None
    assert release_default is not None
    assert release.end_line < release_default.line_number
    assert release_default.resolved_calls == ["alternatives.c::target"]


def test_c_codegraph_keeps_all_structurally_possible_pointer_targets(tmp_path):
    source = tmp_path / "callbacks.c"
    source.write_text(
        "void first(void) {}\n"
        "void second(void) {}\n"
        "void dispatch(int condition) {\n"
        "  void (*callback)(void) = first;\n"
        "  callback();\n"
        "  if (condition) { callback = second; }\n"
        "  callback();\n"
        "}\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    dispatch = graph.nodes["callbacks.c::dispatch"]
    assert dispatch.calls == ["callback"]
    assert dispatch.resolved_calls == [
        "callbacks.c::first",
        "callbacks.c::second",
    ]
    assert [
        (call.kind, call.resolution, call.target_ids) for call in dispatch.call_sites
    ] == [
        ("indirect", "resolved", ("callbacks.c::first",)),
        (
            "indirect",
            "ambiguous",
            ("callbacks.c::first", "callbacks.c::second"),
        ),
    ]
    assert {
        (reference.symbol, reference.target_ids) for reference in dispatch.references
    } >= {
        ("first", ("callbacks.c::first",)),
        ("second", ("callbacks.c::second",)),
    }


def test_c_codegraph_distinguishes_function_pointer_declarator_shapes(tmp_path):
    source = tmp_path / "shapes.c"
    source.write_text(
        "void callback(void) {}\n"
        "void target(void) {}\n"
        "int *pointer_return(void) { return 0; }\n"
        "void adjusted(void callback(void)) { callback(); }\n"
        "void declared(void) {\n"
        "  int *pointer_return(void);\n"
        "  pointer_return();\n"
        "}\n"
        "void indirect(void) {\n"
        "  void (*selected)(void) = target;\n"
        "  selected();\n"
        "}\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    adjusted = graph.nodes["shapes.c::adjusted"]
    assert adjusted.call_sites[0].kind == "indirect"
    assert adjusted.call_sites[0].target_ids == ()
    assert adjusted.resolved_calls == []

    declared = graph.nodes["shapes.c::declared"]
    assert declared.call_sites[0].kind == "direct"
    assert declared.call_sites[0].target_ids == ("shapes.c::pointer_return",)
    assert declared.resolved_calls == ["shapes.c::pointer_return"]

    indirect = graph.nodes["shapes.c::indirect"]
    assert indirect.call_sites[0].kind == "indirect"
    assert indirect.call_sites[0].target_ids == ("shapes.c::target",)
    assert indirect.resolved_calls == ["shapes.c::target"]


def test_c_codegraph_uses_precise_same_file_resolution(tmp_path):
    one = tmp_path / "one.c"
    one.write_text(
        "void target(void) {}\nvoid caller(void) { target(); }\n",
        encoding="utf-8",
    )
    two = tmp_path / "two.c"
    two.write_text("void target(void) {}\n", encoding="utf-8")
    service = _codegraph_service(str(tmp_path), files=(str(one), str(two)))

    graph = service.load(service.materialize())

    caller = graph.nodes["one.c::caller"]
    assert caller.call_sites[0].target_ids == ("one.c::target",)
    assert caller.resolved_calls == ["one.c::target"]


def test_cpp_codegraph_extracts_direct_and_heap_constructor_calls(tmp_path):
    source = tmp_path / "constructors.cpp"
    source.write_text(
        "struct Item { Item(int) {} Item(int, int) {} };\n"
        "void direct() { Item value(1); }\n"
        "void braced() { Item value{2}; }\n"
        "void heap() { new Item(3); }\n"
        "void heap_braced() { new Item{4}; }\n"
        "Item temporary() { return Item{5}; }\n"
        "void consume(Item value);\n"
        "void passed() { consume(Item{6}); }\n"
        "void array_heap() { new Item[2]{7, 8}; }\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())
    constructor = ["constructors.cpp::Item::Item(int)"]

    assert graph.nodes["constructors.cpp::direct()"].resolved_calls == constructor
    assert graph.nodes["constructors.cpp::braced()"].resolved_calls == constructor
    assert graph.nodes["constructors.cpp::heap()"].resolved_calls == constructor
    assert graph.nodes["constructors.cpp::heap_braced()"].resolved_calls == constructor
    assert graph.nodes["constructors.cpp::temporary()"].resolved_calls == constructor
    assert graph.nodes["constructors.cpp::passed()"].resolved_calls == constructor
    assert graph.nodes["constructors.cpp::array_heap()"].resolved_calls == []


def test_c_family_provider_persists_lock_order_facts(tmp_path):
    source = tmp_path / "locks.c"
    source.write_text(
        "void first(void) { mutex_lock(&a); mutex_lock(&b); }\n"
        "void second(void) { mutex_lock(&b); mutex_lock(&a); }\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())
    assert [
        (event.operation, event.lock)
        for event in graph.nodes["locks.c::first"].lock_events
    ] == [
        ("acquire", "a"),
        ("acquire", "b"),
    ]


def test_codegraph_service_applies_configured_annotations(tmp_path):
    service = _codegraph_service(
        str(tmp_path),
        annotation_settings={
            "source_functions": [{"name": "entry", "reason": "test source"}],
            "security_functions": [
                {
                    "name": "danger",
                    "sink_type": "command-injection",
                    "reason": "test sink",
                }
            ],
        },
    )
    base_graph = _graph(
        _fn("src/main.c::main", 1, calls=["entry", "danger"]),
        _fn("src/api.c::entry", 10),
    )
    service._repository.get_code_files = lambda **_kwargs: [
        "src/main.c",
        "src/api.c",
    ]
    service._providers["c_family"].build_graph = lambda **_kwargs: CodeGraphResult(
        base_graph,
        processed_files=("src/main.c", "src/api.c"),
    )
    events = []

    configured = service.load(service.materialize(progress_callback=events.append))

    assert configured.get_node("src/api.c::entry").is_source is True
    assert configured.get_node("src/main.c::main").sink_type == "command_injection"
    assert {event["event"] for event in events} >= {
        "configured_source_functions_done",
        "configured_security_functions_done",
    }


def test_codegraph_service_persists_precise_automatic_sources(tmp_path):
    base_graph = _graph(
        _fn("src/a.c::caller", 1, calls=["callback"]),
        _fn("src/a.c::callback", 2),
        _fn("src/b.c::caller", 1, calls=["callback"]),
        _fn("src/b.c::callback", 2),
        FunctionNode(
            "src/c.c::caller",
            "src/c.c",
            "caller",
            1,
            calls=["api"],
        ),
        FunctionNode(
            "src/c.c::api",
            "src/c.c",
            "api",
            2,
            is_public_entrypoint=True,
            entrypoint_reason="public declaration",
        ),
    )
    base_graph.add_global(
        GlobalConstruct(
            "src/a.c::callbacks",
            "src/a.c",
            "callbacks",
            10,
            referenced_functions=["callback"],
            references=[
                SymbolReference(
                    "callback",
                    10,
                    target_ids=("src/b.c::callback",),
                )
            ],
        )
    )
    base_graph.add_public_declarations({"api": ["include/api.h:2"]})
    service = _codegraph_service(
        str(tmp_path),
        files=("src/a.c", "src/b.c", "src/c.c"),
    )
    service._providers["c_family"].build_graph = lambda **_kwargs: CodeGraphResult(
        base_graph,
        processed_files=("src/a.c", "src/b.c", "src/c.c"),
    )

    annotated = service.load(service.materialize())

    assert annotated.get_node("src/a.c::callback").is_source is False
    assert annotated.get_node("src/b.c::callback").is_source is True
    assert annotated.get_node("src/c.c::api").is_source is True
    assert annotated.get_node("src/c.c::api").source_reason == (
        "public_or_external_entrypoint: public declaration"
    )


def test_codegraph_service_preserves_typed_diagnostics_when_cached(tmp_path):
    service = _codegraph_service(str(tmp_path), files=("one.c",))
    warning = CodeGraphDiagnostic(
        file_path="one.c",
        message="partial parse",
        severity="warning",
        code="codegraph.partial_parse",
        phase="parse",
        line=4,
        start_byte=20,
        end_byte=25,
        partial_output=True,
    )
    service._repository.get_code_files = lambda **_kwargs: ["one.c"]
    service._providers["c_family"].build_graph = lambda **_kwargs: CodeGraphResult(
        CodeGraph(),
        processed_files=("one.c",),
        diagnostics=(warning,),
    )
    first = []
    second = []

    service.materialize(diagnostic_callback=first.append)
    service.materialize(diagnostic_callback=second.append)

    assert first == [warning]
    assert second == [warning]


def test_structured_relationships_affect_cache_keys_and_scoped_copies():
    target = _fn("src/target.c::target", 2)
    caller = _fn("src/caller.c::caller", 1, calls=["target"])
    caller.call_sites = [
        CallSite(
            "target",
            1,
            0,
            start_byte=10,
            end_byte=18,
            target_ids=(target.unique_name,),
        )
    ]
    caller.references = [
        SymbolReference(
            "target",
            1,
            start_byte=10,
            end_byte=16,
            target_ids=(target.unique_name,),
        )
    ]
    graph = _graph(caller, target)
    graph.add_global(
        GlobalConstruct(
            "src/caller.c::callbacks",
            "src/caller.c",
            "callbacks",
            3,
            referenced_functions=["target"],
            references=[
                SymbolReference(
                    "target",
                    3,
                    target_ids=(target.unique_name,),
                )
            ],
        )
    )
    without_references = graph.copy()
    without_references.nodes[caller.unique_name].call_sites = []
    without_references.nodes[caller.unique_name].references = []
    without_references.globals["src/caller.c::callbacks"].references = []

    focus = _copy_graph_nodes(graph, {caller.unique_name})

    assert graph_fingerprint(graph) != graph_fingerprint(without_references)
    assert focus.nodes[caller.unique_name].call_sites[0].target_ids == ()
    assert focus.nodes[caller.unique_name].references[0].target_ids == ()
    assert focus.globals["src/caller.c::callbacks"].references[0].target_ids == ()
    focus.nodes[caller.unique_name].call_sites.clear()
    assert len(graph.nodes[caller.unique_name].call_sites) == 1


@pytest.mark.parametrize(
    ("corrupt", "message"),
    [
        (
            lambda graph: graph.name_index["entry"].append("src/one.c::missing"),
            "name index is corrupt",
        ),
        (
            lambda graph: setattr(
                graph.nodes["src/one.c::entry"], "file_path", "src/unrequested.c"
            ),
            "belongs to unrequested file",
        ),
        (
            lambda graph: graph.nodes["src/one.c::entry"].references.append(
                SymbolReference("missing", 1, target_ids=("src/one.c::missing",))
            ),
            "invalid resolved targets",
        ),
    ],
)
def test_codegraph_service_rejects_provider_graph_corruption(
    tmp_path, corrupt, message
):
    service = _codegraph_service(str(tmp_path), files=("src/one.c",))
    graph = _graph(_fn("src/one.c::entry", 1))
    corrupt(graph)
    service._providers["c_family"].build_graph = lambda **_kwargs: CodeGraphResult(
        graph, processed_files=("src/one.c",)
    )

    result = service.materialize()

    assert result.failed_files == ("src/one.c",)
    assert message in result.diagnostics[0].message


def test_codegraph_service_preserves_provider_resolution_without_cross_links(tmp_path):
    c_graph = _graph(
        _fn("caller.c::entry", 1, calls=["local", "open"]),
        _fn("caller.c::local", 2),
    )
    c_graph.resolve_all_calls()
    python_graph = _graph(_fn("module.py::open", 1))
    progress_events = []
    repository = SimpleNamespace(
        get_code_files=lambda **_kwargs: ["caller.c", "module.py"],
        get_codegraph_registration=lambda path: (
            "c_family" if path.endswith(".c") else "python"
        ),
        get_language_name_for_path=lambda path: (
            "c" if path.endswith(".c") else "python"
        ),
        has_language_file_role=lambda _path, _role: False,
    )

    def provider(file_path, graph):
        def build_graph(*, progress_callback, **_kwargs):
            progress_callback(
                {
                    "event": "codegraph_progress",
                    "completed": 1,
                    "total": 1,
                }
            )
            return CodeGraphResult(graph, processed_files=(file_path,))

        return SimpleNamespace(build_graph=build_graph)

    provider_instances = {
        "c_family": provider(
            "caller.c",
            c_graph,
        ),
        "python": provider(
            "module.py",
            python_graph,
        ),
    }

    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        repository,
        {
            name: (lambda _repository, instance=instance: instance)
            for name, instance in provider_instances.items()
        },
        semantics=CodeGraphSemanticsCatalog(
            providers={"c_family": CFamilyCodeGraphSemantics()},
        ),
    )
    reference = service.materialize(progress_callback=progress_events.append)
    graph = service.load(reference)

    caller = graph.get_node("caller.c::entry")
    assert caller.resolved_calls == ["caller.c::local"]
    assert caller.sink_type == "path_traversal"
    assert graph.get_node("module.py::open").is_public_entrypoint is False
    progress = [
        (event["completed"], event["total"], event["provider"])
        for event in progress_events
        if event["event"] == "codegraph_progress"
    ]
    assert progress == [(1, 2, "c_family"), (2, 2, "python")]


def test_scoped_review_limits_frontier_analysis_to_relevant_graph():
    graph = _graph(
        _fn("src/api.c::api", 1, source=True, calls=["target"]),
        _fn("src/target.c::target", 2, calls=["sink"]),
        _fn("src/sink.c::sink", 3, sink=True),
        _fn("src/unrelated.c::unrelated", 4),
    )
    service = object.__new__(ReachabilityService)
    service._normalize_target_file = lambda file_path: (file_path, file_path)
    frontier_reviewer = Mock()
    frontier_reviewer.review.return_value = SimpleNamespace(
        findings=(),
        failed_node_ids=(),
        failures=(),
        stats=SimpleNamespace(planned_node_count=3, reviewed_node_count=3),
    )
    service._frontier_reviewer = frontier_reviewer

    service.analyze_codebase(
        jobs=Mock(),
        files=["src/target.c"],
        codegraph=graph,
        options=ReachabilityReviewOptions(),
    )

    frontier_graph = frontier_reviewer.review.call_args.args[0]
    assert frontier_reviewer.review.call_args.kwargs["evidence_graph"] is graph
    assert set(frontier_graph.nodes) == {
        "src/api.c::api",
        "src/target.c::target",
        "src/sink.c::sink",
    }


def test_file_review_scans_full_focus():
    graph = _graph(
        _fn(
            "src/main.c::main",
            1,
            source=True,
            calls=["candidate", "uncovered"],
        ),
        _fn("src/review.c::candidate", 10, calls=["extended", "danger"]),
        _fn("src/review.c::extended", 15),
        _fn("src/review.c::uncovered", 20),
        _fn("src/sink.c::danger", 30, sink=True),
    )
    service = object.__new__(ReachabilityService)
    service._normalize_target_file = lambda file_path: (file_path, file_path)
    service._review_options = lambda options: options
    frontier_reviewer = Mock()
    frontier_reviewer.review.return_value = SimpleNamespace(
        findings=(),
        failed_node_ids=(),
        failures=(),
        stats=SimpleNamespace(planned_node_count=5, reviewed_node_count=5),
    )
    service._frontier_reviewer = frontier_reviewer

    service.analyze_file(
        "src/review.c",
        jobs=Mock(),
        options=ReachabilityReviewOptions(),
        codegraph=graph,
    )

    frontier_graph = frontier_reviewer.review.call_args.args[0]
    assert frontier_reviewer.review.call_args.kwargs["evidence_graph"] is graph
    assert set(frontier_graph.nodes) == {
        "src/main.c::main",
        "src/review.c::candidate",
        "src/review.c::extended",
        "src/review.c::uncovered",
        "src/sink.c::danger",
    }


@pytest.mark.parametrize(
    ("graph", "expected_code"),
    [
        (CodeGraph(), "codegraph.empty"),
        (
            _graph(_fn("src/other.c::other", 1)),
            "codegraph.target_missing",
        ),
    ],
)
def test_file_review_reports_missing_codegraph_coverage(graph, expected_code):
    service = object.__new__(ReachabilityService)
    service._normalize_target_file = lambda file_path: (file_path, file_path)
    service._review_options = lambda options: options
    service._frontier_reviewer = Mock()
    diagnostics = []

    analysis = service.analyze_file(
        "src/review.c",
        jobs=Mock(),
        options=ReachabilityReviewOptions(),
        codegraph=graph,
        diagnostic_callback=diagnostics.append,
    )

    assert analysis.codegraph_failures == (f"{expected_code}:src/review.c",)
    assert diagnostics[0].code == expected_code
    service._frontier_reviewer.review.assert_not_called()


def test_c_family_extractor_handles_deep_trees_without_recursion(monkeypatch):
    _patch_ids(monkeypatch)
    extractor = object.__new__(CFamilyTreeSitterExtractor)
    extractor._context = SimpleNamespace(
        get_language_name_for_path=lambda _path: "c",
        has_language_file_role=lambda _path, _role: False,
    )
    deep_fn = _func(
        "deep_fn",
        "void deep_fn(void) { memcpy(dst, src, len); }",
        1,
        child=_deep_chain(1500, _call("memcpy", 1502)),
    )
    functions = extractor._collect_functions(_deep_chain(1500, deep_fn), b"", "deep.c")

    global_decl = _Node(
        "init_declarator",
        text="ops = { .open = deep_open }",
        line=7,
        fields={
            "declarator": _Node("identifier", text="ops", line=7),
            "value": _Node(
                "initializer_list",
                text="{ .open = deep_open }",
                line=7,
                children=[_Node("identifier", text="deep_open", line=7)],
            ),
        },
    )
    globals_, scopes = extractor._collect_globals(
        _deep_chain(1500, global_decl), b"", "deep.c"
    )

    assert [function.node.name for function in functions] == ["deep_fn"]
    assert functions[0].node.calls == ["memcpy"]
    assert globals_[0].referenced_functions == ["deep_open"]
    assert scopes == {"deep.c::ops": ()}
    assert len(globals_) == 1


def test_c_family_ast_helpers_handle_deep_trees_without_recursion():
    ident = _Node("identifier", start_byte=0, end_byte=9)
    root = _deep_chain(
        1500,
        _Node("call_expression", children=[ident], fields={"function": ident}),
    )
    harness = CFamilyAstMixin()

    nodes = list(harness._iter_nodes(root))
    calls = harness._collect_calls_in_scope(root, b"deep_call")

    assert len(nodes) == 1502
    assert calls[0].symbol == "deep_call"


@pytest.mark.parametrize("external", [False, True])
def test_finding_path_annotator(external):
    graph = _graph(
        _fn(
            "src/main.c::main", 1, source=True, calls=["other" if external else "entry"]
        ),
        _fn("src/api.c::entry", 10, calls=["reviewed"]),
        _fn("src/review.c::reviewed", 20, calls=["helper"]),
        _fn("src/review.c::helper", 30),
        _fn("src/other.c::other", 10),
    )
    function = "src/other.c::other" if external else "src/review.c::helper"
    finding = _finding(
        "other" if external else "integer_overflow",
        function,
        10 if external else 30,
        "finding",
        "finding",
    )

    [annotated] = FindingPathAnnotator(graph, "src/review.c").annotate([finding])

    if external:
        assert annotated is finding
    else:
        assert annotated.path == [
            "src/main.c::main",
            "src/api.c::entry",
            "src/review.c::reviewed",
            "src/review.c::helper",
        ]
        assert annotated.source_function == "src/main.c::main"
        assert annotated.sink_function == "src/review.c::helper"
        assert finding.path == ["src/review.c::helper"]
