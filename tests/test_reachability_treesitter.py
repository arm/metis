# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from metis.engine.codegraph import (
    CodeGraph,
    CodeGraphDiagnostic,
    CodeGraphResult,
    FunctionNode,
    GlobalConstruct,
)
from metis.engine.nodes.codegraph import CodeGraphConfiguration
from metis.engine.nodes.codegraph import CodeGraphSemanticsCatalog
from metis.engine.nodes.codegraph import CodeGraphService
from metis.plugins.c_family.ast import CFamilyAstMixin
from metis.plugins.c_family.codegraph import CFamilyCodeGraphProvider
from metis.plugins.c_family.codegraph import CFamilyTreeSitterExtractor
from metis.engine.nodes.reachability import (
    Deduplicator,
    ReachabilityPath,
    SourceRootedPathTracer,
    VulnerabilityFinding,
)
from metis.engine.nodes.reachability.context import ReachabilityContext
from metis.engine.nodes.reachability.file_focus import FileFocusBuilder
from metis.engine.nodes.reachability.finding_identity import _canonical_fields
from metis.engine.nodes.reachability.finding_paths import FindingPathAnnotator
from metis.engine.nodes.reachability.graph_utils import (
    select_confirmation_paths,
)
from metis.engine.nodes.reachability.lock_order import (
    _extract_lock_conflicts,
)
from metis.engine.nodes.reachability.options import ReachabilityReviewOptions
from metis.engine.nodes.reachability.service import ReachabilityService
from metis.plugins.c_plugin import CPlugin
from metis.plugins.c_family.semantics import CFamilyCodeGraphSemantics


def _reachability_context(codegraphs):
    return ReachabilityContext(codegraphs)


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
    plugin = CPlugin(plugin_config={"plugins": {}})
    repository = SimpleNamespace(
        get_code_files=lambda **_kwargs: list(files),
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
        analysis_type="test",
        primary_file=file_path,
        primary_function=function,
        primary_line=line,
        canonical_key=kwargs.get("canonical_key", ""),
    )


TASK_KEY = "src/task.c:src/task.c::task_import:out_of_bounds:unterminated_title"


def _assert_dedup(findings, expected_removed, expected_findings, **kwargs):
    deduped, total, removed = Deduplicator.deduplicate(findings, **kwargs)
    assert (total, removed, deduped) == (
        len(findings),
        expected_removed,
        expected_findings,
    )
    return deduped


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


def test_c_codegraph_preserves_legacy_call_and_initializer_semantics(tmp_path):
    source = tmp_path / "legacy.c"
    source.write_text(
        "struct callbacks { void (*free_fn)(void *); };\n"
        "void target(void) {}\n"
        "void second_target(void) {}\n"
        "void direct(void) { target(); }\n"
        "void second_direct(void) { second_target(); }\n"
        "void release(struct callbacks *png_ptr) {\n"
        "  void (*local)(void) = target;\n"
        "  png_ptr->free_fn(png_ptr);\n"
        "}\n"
        "void second_release(void) {\n"
        "  void (*local)(void) = second_target;\n"
        "}\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    assert graph.nodes["legacy.c::release"].calls == ["png_ptr"]
    assert "legacy.c::local" in graph.globals
    assert graph.nodes["legacy.c::target"].is_source is True
    assert graph.nodes["legacy.c::second_target"].is_source is True


def test_cpp_codegraph_preserves_scoped_overloads_and_special_members(tmp_path):
    source = tmp_path / "scopes.cpp"
    source.write_text(
        "namespace first { void visit(int value) {} }\n"
        "namespace second { void visit(int value) {} }\n"
        "namespace api {\n"
        "class Worker {\n"
        "public:\n"
        "  ~Worker() {}\n"
        "  int operator()(int value) { return value; }\n"
        "  void run(int value) {}\n"
        "  void run(double value) {}\n"
        "};\n"
        "class Declared { public: void execute(int value); };\n"
        "void Declared::execute(int value) {}\n"
        "}\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    assert set(graph.nodes) == {
        "scopes.cpp::first::visit(int)",
        "scopes.cpp::second::visit(int)",
        "scopes.cpp::api::Worker::~Worker()",
        "scopes.cpp::api::Worker::operator()(int)",
        "scopes.cpp::api::Worker::run(int)",
        "scopes.cpp::api::Worker::run(double)",
        "scopes.cpp::api::Declared::execute(int)",
    }


def test_cpp_codegraph_uses_available_call_syntax_conservatively(tmp_path):
    source = tmp_path / "calls.cpp"
    source.write_text(
        "namespace api {\n"
        "void overloaded(int value) {}\n"
        "void overloaded(double value) {}\n"
        "void arity(int value) {}\n"
        "void arity(int first, int second) {}\n"
        "class Worker {\n"
        "public:\n"
        "  void member(int value) {}\n"
        "  void call_member() { this->member(1); }\n"
        "};\n"
        "void call_object(Worker &worker) { worker.member(1); }\n"
        "void call_overload() { overloaded(1); }\n"
        "void call_arity() { arity(1, 2); }\n"
        "}\n"
        "namespace other {\n"
        "void overloaded(int value) {}\n"
        "class Worker { public: void member(int value) {} };\n"
        "}\n"
        "void call_qualified() { other::overloaded(1); }\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    assert graph.nodes["calls.cpp::api::Worker::call_member()"].resolved_calls == [
        "calls.cpp::api::Worker::member(int)"
    ]
    assert graph.nodes["calls.cpp::api::call_overload()"].resolved_calls == [
        "calls.cpp::api::overloaded(int)",
        "calls.cpp::api::overloaded(double)",
    ]
    assert graph.nodes["calls.cpp::api::call_arity()"].resolved_calls == [
        "calls.cpp::api::arity(int,int)"
    ]
    object_call = graph.nodes["calls.cpp::api::call_object(Worker&)"]
    assert object_call.calls == ["member"]
    assert object_call.resolved_calls == []
    assert graph.nodes["calls.cpp::call_qualified()"].resolved_calls == [
        "calls.cpp::other::overloaded(int)"
    ]


def test_cpp_codegraph_respects_required_default_and_variadic_arity(tmp_path):
    source = tmp_path / "arity.cpp"
    source.write_text(
        "void required(int value) {}\n"
        "void required(int first, int second) {}\n"
        "void defaults(int required, int optional = 1) {}\n"
        "void variadic(int required, ...) {}\n"
        "void call_required() { required(1); }\n"
        "void call_defaults() { defaults(1); }\n"
        "void call_variadic_too_few() { variadic(); }\n"
        "void call_variadic() { variadic(1, 2); }\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    assert graph.nodes["arity.cpp::call_required()"].resolved_calls == [
        "arity.cpp::required(int)"
    ]
    assert graph.nodes["arity.cpp::call_defaults()"].resolved_calls == [
        "arity.cpp::defaults(int,int)"
    ]
    assert graph.nodes["arity.cpp::call_variadic_too_few()"].resolved_calls == []
    assert graph.nodes["arity.cpp::call_variadic()"].resolved_calls == [
        "arity.cpp::variadic(int,...)"
    ]


def test_cpp_codegraph_uses_default_arity_from_header_declaration(tmp_path):
    header = tmp_path / "defaults.hpp"
    source = tmp_path / "header_default.cpp"
    header.write_text(
        "namespace api { void optional(int value = 0); }\n",
        encoding="utf-8",
    )
    source.write_text(
        '#include "defaults.hpp"\n'
        "namespace api {\n"
        "void optional(int value) {}\n"
        "void caller() { optional(); }\n"
        "}\n",
        encoding="utf-8",
    )
    service = _codegraph_service(
        str(tmp_path),
        files=(str(header), str(source)),
    )

    graph = service.load(service.materialize())

    assert graph.nodes["header_default.cpp::api::caller()"].resolved_calls == [
        "header_default.cpp::api::optional(int)"
    ]


def test_cpp_codegraph_matches_equivalent_parameter_types_for_defaults(tmp_path):
    source = tmp_path / "equivalent_parameters.cpp"
    source.write_text(
        "void qualified(const int value = 0);\n"
        "void adjusted(int values[4] = nullptr);\n"
        "void pointer(int ** const value = nullptr);\n"
        "void matrix(int values[3][4] = nullptr);\n"
        "void caller() { qualified(); adjusted(); pointer(); matrix(); }\n"
        "void qualified(int value) {}\n"
        "void adjusted(int *values) {}\n"
        "void pointer(int **value) {}\n"
        "void matrix(int (*values)[4]) {}\n"
        "void distinct(int **value) {}\n"
        "void distinct(int * const *value) {}\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    assert graph.nodes["equivalent_parameters.cpp::caller()"].resolved_calls == [
        "equivalent_parameters.cpp::adjusted(int*)",
        "equivalent_parameters.cpp::matrix(int(*)[4])",
        "equivalent_parameters.cpp::pointer(int**)",
        "equivalent_parameters.cpp::qualified(int)",
    ]
    assert "equivalent_parameters.cpp::distinct(int**)" in graph.nodes
    assert "equivalent_parameters.cpp::distinct(int*const*)" in graph.nodes


def test_cpp_codegraph_keeps_internal_calls_in_their_translation_unit(tmp_path):
    first = tmp_path / "first.cpp"
    second = tmp_path / "second.cpp"
    first.write_text(
        "static void local() {}\nvoid caller() { local(); }\n",
        encoding="utf-8",
    )
    second.write_text("static void local() {}\n", encoding="utf-8")
    service = _codegraph_service(
        str(tmp_path),
        files=(str(first), str(second)),
    )

    graph = service.load(service.materialize())

    assert graph.nodes["first.cpp::caller()"].resolved_calls == ["first.cpp::local()"]


def test_cpp_codegraph_handles_anonymous_namespace_linkage(tmp_path):
    first = tmp_path / "first.cpp"
    second = tmp_path / "second.cpp"
    first.write_text(
        "namespace { void hidden() {} }\n"
        "namespace owner {\n"
        "namespace { void scoped() {} }\n"
        "void inside() { scoped(); }\n"
        "}\n"
        "namespace { struct HiddenApi { static void run() {} }; }\n"
        "void qualified() { HiddenApi::run(); }\n"
        "void qualified_scoped() { owner::scoped(); }\n"
        "namespace unrelated { void outside() { scoped(); } }\n"
        "void caller() { hidden(); }\n",
        encoding="utf-8",
    )
    second.write_text("namespace { void hidden() {} }\n", encoding="utf-8")
    service = _codegraph_service(
        str(tmp_path),
        files=(str(first), str(second)),
    )

    graph = service.load(service.materialize())
    first_hidden = "first.cpp::(anonymous namespace)::hidden()"

    assert graph.nodes[first_hidden].has_internal_linkage
    assert graph.nodes["first.cpp::caller()"].resolved_calls == [first_hidden]
    scoped = "first.cpp::owner::(anonymous namespace)::scoped()"
    assert graph.nodes["first.cpp::owner::inside()"].resolved_calls == [scoped]
    assert graph.nodes["first.cpp::unrelated::outside()"].resolved_calls == []
    assert graph.nodes["first.cpp::qualified()"].resolved_calls == [
        "first.cpp::(anonymous namespace)::HiddenApi::run()"
    ]
    assert graph.nodes["first.cpp::qualified_scoped()"].resolved_calls == [scoped]


def test_cpp_codegraph_resolves_explicit_template_qualification(tmp_path):
    source = tmp_path / "templates.cpp"
    source.write_text(
        "namespace first { template<class T> void run(T value) {} }\n"
        "namespace second { template<class T> void run(T value) {} }\n"
        "void caller() { first::run<int>(1); }\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    assert graph.nodes["templates.cpp::caller()"].resolved_calls == [
        "templates.cpp::first::run(T)"
    ]


@pytest.mark.parametrize(
    ("extension", "expected_id"),
    [("c", "alternatives.c::selected"), ("cpp", "alternatives.cpp::selected(int)")],
)
def test_c_family_codegraph_deduplicates_preprocessor_alternatives(
    tmp_path,
    extension,
    expected_id,
):
    source = tmp_path / f"alternatives.{extension}"
    source.write_text(
        "#if FIRST\n"
        "void selected(int first) {}\n"
        "#else\n"
        "void selected(int second) {}\n"
        "#endif\n",
        encoding="utf-8",
    )
    service = _codegraph_service(str(tmp_path), files=(str(source),))

    graph = service.load(service.materialize())

    assert list(graph.nodes) == [expected_id]


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
    conflicts = _extract_lock_conflicts(graph)

    assert [
        (event.operation, event.lock)
        for event in graph.nodes["locks.c::first"].lock_events
    ] == [
        ("acquire", "a"),
        ("acquire", "b"),
    ]
    assert len(conflicts) == 1
    assert {conflicts[0][2].name, conflicts[0][4].name} == {"first", "second"}


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
        )
    )
    service = _codegraph_service(
        str(tmp_path),
        files=("src/a.c", "src/b.c", "src/c.c"),
    )
    service._providers["c_family"].build_graph = lambda **_kwargs: CodeGraphResult(
        base_graph,
        processed_files=("src/a.c", "src/b.c", "src/c.c"),
    )

    annotated = service.load(service.materialize())

    assert annotated.get_node("src/a.c::callback").is_source is True
    assert annotated.get_node("src/b.c::callback").is_source is False
    assert annotated.get_node("src/c.c::api").is_source is False


def test_codegraph_service_preserves_typed_diagnostics_when_cached(tmp_path):
    service = _codegraph_service(str(tmp_path), files=("one.c",))
    warning = CodeGraphDiagnostic(
        file_path="one.c",
        message="partial parse",
        severity="warning",
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


@pytest.mark.parametrize(
    ("corrupt", "message"),
    [
        (
            lambda graph: graph.name_index["entry"].append("src/one.c::missing"),
            "name index is corrupt",
        ),
        (
            lambda graph: setattr(
                graph.nodes["src/one.c::entry"],
                "file_path",
                "src/unrequested.c",
            ),
            "belongs to unrequested file",
        ),
        (
            lambda graph: graph.nodes["src/one.c::entry"].resolved_calls.append(
                "src/one.c::missing"
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


def test_codegraph_rejects_duplicate_ids_and_keeps_separate_global_namespace():
    graph = CodeGraph()
    node = _fn("src/one.c::entry", 1)
    graph.add_node(node)

    with pytest.raises(ValueError, match="Duplicate code graph node ID"):
        graph.add_node(node)
    graph.add_global(
        GlobalConstruct(
            unique_name=node.unique_name,
            file_path=node.file_path,
            name=node.name,
            line_number=node.line_number,
        )
    )

    assert graph.nodes[node.unique_name] is node
    assert graph.globals[node.unique_name].name == node.name


def test_codegraph_service_omits_files_without_an_installed_provider(tmp_path):
    service = _codegraph_service(str(tmp_path), files=("one.c",))
    service._providers = {}
    service._provider_factories = {}

    reference = service.materialize()

    assert service.load(reference).node_count() == 0
    assert reference.failed_files == ()


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


@pytest.mark.parametrize(
    ("nodes", "expected", "sink", "sink_type"),
    [
        (
            [
                _fn("src/main.c::main", 1, source=True, calls=["a"]),
                _fn("src/a.c::a", 10, calls=["d"]),
                _fn("src/d.c::d", 20, calls=["e"]),
                _fn("src/e.c::e", 30),
            ],
            ["src/main.c::main", "src/a.c::a", "src/d.c::d", "src/e.c::e"],
            "src/e.c::e",
            "reachable_endpoint",
        ),
        (
            [
                _fn("src/main.c::main", 1, source=True, calls=["a"]),
                _fn("src/a.c::a", 10, calls=["b"]),
                _fn("src/b.c::b", 20, calls=["a"]),
            ],
            ["src/main.c::main", "src/a.c::a", "src/b.c::b"],
            None,
            None,
        ),
    ],
)
def test_source_rooted_tracer_paths(nodes, expected, sink, sink_type):
    paths = SourceRootedPathTracer(_graph(*nodes)).find_all_paths()
    assert [path.path for path in paths] == [expected]
    if sink:
        assert paths[0].sink == sink
        assert paths[0].sink_type == sink_type


def test_source_rooted_tracer_keeps_sink_before_terminal_callee():
    graph = _graph(
        _fn("src/main.c::main", 1, source=True, calls=["danger"]),
        _fn("src/danger.c::danger", 10, sink=True, calls=["cleanup"]),
        _fn("src/cleanup.c::cleanup", 20),
    )

    paths = SourceRootedPathTracer(graph).find_all_paths()

    assert [(path.sink, path.sink_type) for path in paths] == [
        ("src/danger.c::danger", "other"),
        ("src/cleanup.c::cleanup", "reachable_endpoint"),
    ]


def test_source_rooted_tracer_does_not_drop_late_sink_branches():
    source = _fn("src/main.c::main", 1, source=True)
    graph = _graph(source)
    for index in range(201):
        name = f"leaf_{index:03d}"
        source.calls.append(name)
        graph.add_node(
            _fn(
                f"src/{name}.c::{name}",
                index + 2,
                sink=index == 200,
            )
        )
    graph.resolve_all_calls()

    paths = SourceRootedPathTracer(graph).find_all_paths()

    assert len(paths) == 201
    assert any(path.sink == "src/leaf_200.c::leaf_200" for path in paths)


def test_source_rooted_tracer_keeps_both_routes_through_a_diamond():
    graph = _graph(
        _fn("src/main.c::main", 1, source=True, calls=["left", "right"]),
        _fn("src/left.c::left", 2, calls=["sink"]),
        _fn("src/right.c::right", 3, calls=["sink"]),
        _fn("src/sink.c::sink", 4, sink=True),
    )

    paths = SourceRootedPathTracer(graph).find_all_paths()

    assert {tuple(path.path) for path in paths} == {
        ("src/main.c::main", "src/left.c::left", "src/sink.c::sink"),
        ("src/main.c::main", "src/right.c::right", "src/sink.c::sink"),
    }


def test_scoped_review_limits_supplementary_analysis_to_relevant_paths():
    graph = _graph(
        _fn("src/api.c::api", 1, source=True, calls=["target"]),
        _fn("src/target.c::target", 2, calls=["sink"]),
        _fn("src/sink.c::sink", 3, sink=True),
        _fn("src/unrelated.c::unrelated", 4),
    )
    path = ReachabilityPath(
        "src/api.c::api",
        "src/sink.c::sink",
        ["src/api.c::api", "src/target.c::target", "src/sink.c::sink"],
        "other",
    )
    service = object.__new__(ReachabilityService)
    service._context = SimpleNamespace(
        graph_and_paths=lambda **_kwargs: (graph, [path]),
    )
    service._normalize_target_file = lambda file_path: (file_path, file_path)
    service._review_model = lambda _options: "test-model"
    service._supplementary_for_graph = Mock(return_value=[])
    service._finalize_findings = Mock(return_value=([], 0, 0))

    service.analyze_codebase(
        files=["src/target.c"],
        codegraph=graph,
        options=ReachabilityReviewOptions(confirm_paths=False),
    )

    supplementary_graph = service._supplementary_for_graph.call_args.args[0]
    assert set(supplementary_graph.nodes) == {
        "src/api.c::api",
        "src/target.c::target",
        "src/sink.c::sink",
    }


def test_reachability_service_auto_caps_confirmation_paths():
    source = _fn("src/main.c::main", 1, source=True)
    graph = _graph(source)
    for idx in range(80):
        source.calls.append(f"leaf_{idx}")
        graph.add_node(_fn(f"src/leaf_{idx}.c::leaf_{idx}", idx + 2, sink=idx % 3 == 0))
    graph.resolve_all_calls()

    paths = SourceRootedPathTracer(graph).find_all_paths()
    selected = select_confirmation_paths(paths, graph)

    assert len(paths) == 80
    assert len(selected) == 12
    assert len({path.sink for path in selected}) == 12
    assert any(graph.get_node(path.sink).is_sink for path in selected)


def test_explicit_confirmation_limit_prefers_security_sink():
    graph = _graph(
        _fn("src/main.c::main", 1, source=True, calls=["ordinary", "danger"]),
        _fn("src/a.c::ordinary", 2),
        _fn("src/z.c::danger", 3, sink=True),
    )

    selected = select_confirmation_paths(
        SourceRootedPathTracer(graph).find_all_paths(),
        graph,
        max_paths=1,
    )

    assert [path.sink for path in selected] == ["src/z.c::danger"]


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
    globals_, refs = extractor._collect_globals(
        _deep_chain(1500, global_decl), b"", "deep.c"
    )

    assert [function.node.name for function in functions] == ["deep_fn"]
    assert functions[0].node.calls == ["memcpy"]
    assert refs == {"deep_open"}
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


def test_file_focus_prefers_source_to_reviewed_file_paths():
    graph = _graph(
        _fn("src/main.c::main", 1, source=True, calls=["entry"]),
        _fn("src/api.c::entry", 10, calls=["reviewed"]),
        _fn("src/review.c::reviewed", 20, calls=["danger"]),
        _fn("src/sink.c::danger", 30, sink=True),
    )

    focus = FileFocusBuilder(graph).build("src/review.c")

    assert [path.path for path in focus.incoming_paths] == [
        ["src/main.c::main", "src/api.c::entry", "src/review.c::reviewed"]
    ]
    assert [path.path for path in focus.outgoing_context_paths] == [
        ["src/review.c::reviewed", "src/sink.c::danger"]
    ]
    assert "src/sink.c::danger" in focus.node_names


def test_file_focus_dedupes_near_duplicate_source_target_paths():
    graph = _graph(
        _fn("src/main.c::main", 1, source=True, calls=["wrap_a", "wrap_b", "wrap_c"]),
        _fn("src/a.c::wrap_a", 10, calls=["reviewed"]),
        _fn("src/b.c::wrap_b", 20, calls=["reviewed"]),
        _fn("src/c.c::wrap_c", 30, calls=["reviewed"]),
        _fn("src/review.c::reviewed", 40),
    )

    focus = FileFocusBuilder(graph, max_path_variants_per_source_target=2).build(
        "src/review.c"
    )

    assert len(focus.incoming_paths) == 2
    assert all(path.source == "src/main.c::main" for path in focus.incoming_paths)
    assert all(path.sink == "src/review.c::reviewed" for path in focus.incoming_paths)


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


def test_deduplicator_keeps_same_canonical_key_without_llm_grouping():
    findings = [
        _finding(
            "missing_bounds_check",
            "src/task.c::task_import",
            63,
            "Import passes a length-delimited title to task_create.",
            "title import buffer not terminated before task_create strlen",
            canonical_key=TASK_KEY,
            path=["src/api.c::dispatch", "src/task.c::task_import"],
        ),
        _finding(
            "out_of_bounds",
            "src/task.c::task_import",
            64,
            "The same title slice can be read past its end.",
            "unterminated title reaches strlen",
            canonical_key=TASK_KEY,
            path=["src/io.c::read_task", "src/task.c::task_import"],
        ),
    ]

    _assert_dedup(findings, 0, findings)


def test_canonical_fields_build_deterministic_key_from_root_cause_id():
    fields = _canonical_fields(
        {
            "primary_file": "src/task.c",
            "primary_function": "src/task.c::task_import",
            "primary_line": 64,
            "root_cause_id": "unterminated_title",
            "canonical_key": "ignored/free-form/prefix:other_token",
        },
        default_file="src/fallback.c",
        default_function="src/fallback.c::fallback",
        default_line=1,
        vulnerability_type="missing_bounds_check",
    )

    assert fields == (
        "src/task.c",
        "src/task.c::task_import",
        64,
        "src/task.c:src/task.c::task_import:missing_bounds_check:unterminated_title",
    )


def test_deduplicator_drops_later_duplicate_indexes_from_llm_grouping():
    findings = [
        _finding(
            "missing_bounds_check",
            "src/task.c::task_import",
            63,
            "Import passes a length-delimited title to task_create.",
            "title import buffer not terminated before task_create strlen",
            canonical_key=TASK_KEY,
        ),
        _finding(
            "out_of_bounds",
            "src/task.c::task_import",
            64,
            "The same title slice can be read past its end.",
            "unterminated title reaches strlen",
            canonical_key="task_import:memory_bounds:unterminated_title",
        ),
    ]
    seen_indexes = []

    def adjudicator(candidates):
        seen_indexes.extend(candidate["index"] for candidate in candidates)
        return {
            "groups": [
                {
                    "member_indexes": [0, 1],
                    "relationship": "duplicate",
                    "reason": "same issue",
                }
            ]
        }

    _assert_dedup(findings, 1, [findings[0]], final_adjudicator=adjudicator)
    assert seen_indexes == [0, 1]
    assert findings[0].vulnerability_type == "missing_bounds_check"
    assert findings[1].canonical_key == "task_import:memory_bounds:unterminated_title"


def test_deduplicator_keeps_llm_representative_duplicate_index():
    key = "src/dispatch.c:src/dispatch.c::handle_reset:missing_auth:reset_missing_permission"
    vague = _finding(
        "missing_auth",
        "src/dispatch.c::handle_reset",
        0,
        "Reset is missing an authorization check.",
        "",
        canonical_key=key,
        path=["src/dispatch.c::handle_reset"],
    )
    vague.primary_line = 0
    vague.evidence = vague.mitigation = ""
    specific = _finding(
        "missing_auth",
        "src/dispatch.c::handle_reset",
        88,
        "handle_reset dispatches the privileged reset operation before checking reset permission.",
        "reset operation reaches device_reset without reset-specific permission",
        canonical_key=key,
        path=["src/api.c::dispatch", "src/dispatch.c::handle_reset"],
    )
    specific.mitigation = (
        "Require reset-specific permission before calling device_reset."
    )

    def adjudicator(_candidates):
        return {
            "groups": [
                {
                    "member_indexes": [0, 1],
                    "relationship": "duplicate",
                    "representative_index": 1,
                }
            ]
        }

    _assert_dedup([vague, specific], 1, [specific], final_adjudicator=adjudicator)


def test_deduplicator_keeps_different_canonical_keys_in_same_location():
    findings = [
        _finding(
            "missing_auth",
            "src/dispatch.c::handle_task_update",
            80,
            "Task update treats auth_get_level as a boolean.",
            "auth level boolean gate for task update",
            canonical_key="src/dispatch.c:src/dispatch.c::handle_task_update:missing_auth:boolean_gate",
        ),
        _finding(
            "missing_auth",
            "src/dispatch.c::handle_task_update",
            82,
            "Task update does not verify that the session owns the task.",
            "missing owner check before task update",
            canonical_key="src/dispatch.c:src/dispatch.c::handle_task_update:missing_auth:owner_check",
        ),
    ]

    _assert_dedup(findings, 0, findings)


def test_deduplicator_keeps_all_findings_when_adjudicator_is_invalid():
    findings = [
        _finding(
            "array_index_size_mismatch",
            "src/dispatch.c::dispatch",
            198,
            "priority_counts is indexed with msg.flags & 0x0F.",
            "masked array index can exceed priority_counts length",
        ),
        _finding(
            "array_oob",
            "src/dispatch.c::dispatch",
            199,
            "The priority_counts index allows values 0 through 15.",
            "0x0F masked index can exceed the array bounds",
        ),
    ]

    deduped = _assert_dedup(
        findings, 0, findings, final_adjudicator=lambda _candidates: {"not_groups": []}
    )
    assert [finding.vulnerability_type for finding in deduped] == [
        "array_index_size_mismatch",
        "array_oob",
    ]


def test_deduplicator_does_not_cap_without_llm_grouping():
    findings = [
        _finding(
            "missing_auth",
            "src/dispatch.c::handle_task_update",
            80 + index,
            f"Missing authorization check {index}.",
            f"missing authorization check {index}",
            canonical_key=f"src/dispatch.c:src/dispatch.c::handle_task_update:missing_auth:check_{index}",
            path=[f"src/api.c::entry_{index}", "src/dispatch.c::handle_task_update"],
        )
        for index in range(4)
    ]

    _assert_dedup(findings, 0, findings, max_per_sink=2)
