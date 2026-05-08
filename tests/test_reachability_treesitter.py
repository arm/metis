# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.reachability_service import PathTracer
from metis.engine.analysis.c_family_analyzer_common import _identifier_from_node
from metis.engine.analysis.c_family_ast import CFamilyAstMixin
from metis.engine.reachability_common import FunctionNode, ReachabilityGraph
from metis.engine.reachability_service_modular.builder import (
    TreeSitterReachabilityGraphBuilder,
)
from metis.engine.reachability_service_modular.c_family import (
    CFamilyTreeSitterExtractor,
)
from metis.engine.reachability_service_modular.file_focus import FileFocusBuilder
from metis.engine.reachability_service_modular.finding_paths import FindingPathAnnotator
from metis.engine.reachability_common import VulnerabilityFinding


class _Node:
    def __init__(self, node_type, *, text="", line=1, children=None, fields=None):
        self.type = node_type
        self.text = text
        self.start_point = (line - 1, 0)
        self.end_point = (line - 1, 0)
        self.start_byte = 0
        self.end_byte = 0
        self.children = children or []
        self._fields = fields or {}

    def child_by_field_name(self, name):
        return self._fields.get(name)


class _Tree:
    def __init__(self, root):
        self.root_node = root


class _Parsed:
    def __init__(self, root):
        self.text = ""
        self.tree = _Tree(root)


class _Runtime:
    is_available = True
    init_error = ""

    def __init__(self, root):
        self._root = root

    def parse_file(self, _codebase_path, _rel_path):
        return _Parsed(self._root)


def test_treesitter_builder_extracts_reachability_graph(monkeypatch):
    import metis.engine.reachability_service_modular.c_family as c_family

    monkeypatch.setattr(c_family, "_node_text", lambda node, _source: node.text)
    monkeypatch.setattr(
        c_family,
        "_identifier_from_node",
        lambda node, _source: getattr(node, "text", "") if node else "",
    )

    foo_call_ident = _Node("identifier", text="foo", line=3)
    foo_call = _Node("call_expression", line=3, fields={"function": foo_call_ident})
    main_def = _Node(
        "function_definition",
        text="int main(int argc, char **argv) { foo(argv[1]); }",
        line=1,
        children=[foo_call],
        fields={
            "declarator": _Node("function_declarator", text="main", line=1)
        },
    )

    memcpy_ident = _Node("identifier", text="memcpy", line=8)
    memcpy_call = _Node("call_expression", line=8, fields={"function": memcpy_ident})
    foo_def = _Node(
        "function_definition",
        text="void foo(char *src) { char dst[8]; memcpy(dst, src, 64); }",
        line=6,
        children=[memcpy_call],
        fields={
            "declarator": _Node("function_declarator", text="foo", line=6)
        },
    )

    root = _Node("translation_unit", children=[main_def, foo_def])

    builder = TreeSitterReachabilityGraphBuilder()
    builder._extractor._runtimes = {"c": _Runtime(root)}

    graph = builder.build(["main.c"], ".")

    assert graph.node_count() == 2
    assert graph.get_node("main.c::main").is_source is True
    assert graph.get_node("main.c::foo").is_sink is True
    assert graph.get_node("main.c::foo").sink_type == "buffer_overflow"
    assert graph.get_node("main.c::main").resolved_calls == ["main.c::foo"]

    paths = PathTracer(graph).find_all_paths()
    assert paths
    assert paths[0].path == ["main.c::main", "main.c::foo"]


def _deep_chain(depth, leaf):
    node = leaf
    for idx in range(depth):
        node = _Node(f"wrapper_{idx}", children=[node])
    return node


def test_identifier_extraction_handles_deep_trees_without_recursion():
    leaf = _Node("identifier")
    leaf.start_byte = 0
    leaf.end_byte = 8
    root = _deep_chain(1500, leaf)

    assert _identifier_from_node(root, b"deep_sym") == "deep_sym"


def test_c_family_extractor_handles_deep_trees_without_recursion(monkeypatch):
    import metis.engine.reachability_service_modular.c_family as c_family

    monkeypatch.setattr(c_family, "_node_text", lambda node, _source: node.text)
    monkeypatch.setattr(
        c_family,
        "_identifier_from_node",
        lambda node, _source: getattr(node, "text", "") if node else "",
    )

    extractor = object.__new__(CFamilyTreeSitterExtractor)

    memcpy_ident = _Node("identifier", text="memcpy", line=1502)
    memcpy_call = _Node("call_expression", line=1502, fields={"function": memcpy_ident})
    deep_body = _deep_chain(1500, memcpy_call)
    deep_fn = _Node(
        "function_definition",
        text="void deep_fn(void) { memcpy(dst, src, len); }",
        line=1,
        children=[deep_body],
        fields={"declarator": _Node("function_declarator", text="deep_fn", line=1)},
    )
    function_root = _deep_chain(1500, deep_fn)

    nodes = extractor._collect_functions(function_root, b"", "deep.c", set())

    assert [node.name for node in nodes] == ["deep_fn"]
    assert nodes[0].calls == ["memcpy"]

    global_decl = _Node(
        "declaration",
        text="static const struct file_operations ops = { .open = deep_open };",
        line=7,
        fields={"declarator": _Node("identifier", text="ops", line=7)},
    )
    global_root = _deep_chain(1500, global_decl)

    globals_, refs = extractor._collect_globals(global_root, b"", "deep.c")

    assert refs == {"deep_open"}
    assert len(globals_) == 1


class _AstHarness(CFamilyAstMixin):
    pass


def test_c_family_ast_helpers_handle_deep_trees_without_recursion():
    harness = _AstHarness()
    ident = _Node("identifier")
    ident.start_byte = 0
    ident.end_byte = 9
    call = _Node(
        "call_expression",
        children=[ident],
        fields={"function": ident},
    )
    root = _deep_chain(1500, call)
    source = b"deep_call"

    nodes, parent_map = harness._index_tree(root)
    calls = harness._collect_calls(root, source)
    refs = harness._collect_references(root, source)

    assert len(nodes) == 1502
    assert parent_map[id(root)] is None
    assert calls["deep_call"][0].symbol == "deep_call"
    assert refs["deep_call"][0].symbol == "deep_call"


def _fn(unique, file_path, name, line, *, source=False, sink=False, calls=None):
    return FunctionNode(
        unique_name=unique,
        file_path=file_path,
        name=name,
        line_number=line,
        is_source=source,
        is_sink=sink,
        calls=list(calls or []),
        sink_type="other" if sink else "",
    )


def test_file_focus_prefers_source_to_reviewed_file_paths():
    graph = ReachabilityGraph()
    for node in [
        _fn("src/main.c::main", "src/main.c", "main", 1, source=True, calls=["entry"]),
        _fn("src/api.c::entry", "src/api.c", "entry", 10, calls=["reviewed"]),
        _fn("src/review.c::reviewed", "src/review.c", "reviewed", 20, calls=["danger"]),
        _fn("src/sink.c::danger", "src/sink.c", "danger", 30, sink=True),
    ]:
        graph.add_node(node)
    graph.resolve_all_calls()

    focus = FileFocusBuilder(graph).build("src/review.c")

    assert [path.path for path in focus.incoming_paths] == [
        ["src/main.c::main", "src/api.c::entry", "src/review.c::reviewed"]
    ]
    assert [path.path for path in focus.outgoing_context_paths] == [
        ["src/review.c::reviewed", "src/sink.c::danger"]
    ]
    assert "src/sink.c::danger" in focus.node_names


def test_file_focus_dedupes_near_duplicate_source_target_paths():
    graph = ReachabilityGraph()
    for node in [
        _fn(
            "src/main.c::main",
            "src/main.c",
            "main",
            1,
            source=True,
            calls=["wrap_a", "wrap_b", "wrap_c"],
        ),
        _fn("src/a.c::wrap_a", "src/a.c", "wrap_a", 10, calls=["reviewed"]),
        _fn("src/b.c::wrap_b", "src/b.c", "wrap_b", 20, calls=["reviewed"]),
        _fn("src/c.c::wrap_c", "src/c.c", "wrap_c", 30, calls=["reviewed"]),
        _fn("src/review.c::reviewed", "src/review.c", "reviewed", 40),
    ]:
        graph.add_node(node)
    graph.resolve_all_calls()

    focus = FileFocusBuilder(
        graph,
        max_path_variants_per_source_target=2,
    ).build("src/review.c")

    assert len(focus.incoming_paths) == 2
    assert all(path.source == "src/main.c::main" for path in focus.incoming_paths)
    assert all(path.sink == "src/review.c::reviewed" for path in focus.incoming_paths)


def test_finding_path_annotator_attaches_source_to_defect_path():
    graph = ReachabilityGraph()
    for node in [
        _fn("src/main.c::main", "src/main.c", "main", 1, source=True, calls=["entry"]),
        _fn("src/api.c::entry", "src/api.c", "entry", 10, calls=["reviewed"]),
        _fn("src/review.c::reviewed", "src/review.c", "reviewed", 20, calls=["helper"]),
        _fn("src/review.c::helper", "src/review.c", "helper", 30),
    ]:
        graph.add_node(node)
    graph.resolve_all_calls()

    finding = VulnerabilityFinding(
        id="finding1",
        vulnerability_type="integer_overflow",
        severity="high",
        confidence="high",
        source_function="src/review.c::helper",
        source_file="src/review.c",
        source_line=30,
        sink_function="src/review.c::helper",
        sink_file="src/review.c",
        sink_line=30,
        path=["src/review.c::helper"],
        description="helper has unchecked arithmetic",
        primary_file="src/review.c",
        primary_function="src/review.c::helper",
        primary_line=30,
    )

    [annotated] = FindingPathAnnotator(graph, "src/review.c").annotate([finding])

    assert annotated.path == [
        "src/main.c::main",
        "src/api.c::entry",
        "src/review.c::reviewed",
        "src/review.c::helper",
    ]
    assert annotated.source_function == "src/main.c::main"
    assert annotated.sink_function == "src/review.c::helper"
    assert finding.path == ["src/review.c::helper"]


def test_finding_path_annotator_leaves_external_primary_file_unchanged():
    graph = ReachabilityGraph()
    for node in [
        _fn("src/main.c::main", "src/main.c", "main", 1, source=True, calls=["other"]),
        _fn("src/other.c::other", "src/other.c", "other", 10),
    ]:
        graph.add_node(node)
    graph.resolve_all_calls()

    finding = VulnerabilityFinding(
        id="finding2",
        vulnerability_type="other",
        severity="high",
        confidence="high",
        source_function="src/other.c::other",
        source_file="src/other.c",
        source_line=10,
        sink_function="src/other.c::other",
        sink_file="src/other.c",
        sink_line=10,
        path=["src/other.c::other"],
        primary_file="src/other.c",
        primary_function="src/other.c::other",
        primary_line=10,
    )

    [annotated] = FindingPathAnnotator(graph, "src/review.c").annotate([finding])

    assert annotated is finding
