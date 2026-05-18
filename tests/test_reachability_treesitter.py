# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.analysis.c_family_ast import CFamilyAstMixin
from metis.engine.reachability import (
    Deduplicator,
    FunctionNode,
    ReachabilityGraph,
    SourceRootedPathTracer,
)
from metis.engine.reachability.finding_normalization import (
    _canonical_fields,
    _confidence_score,
)
from metis.engine.reachability.graph_utils import select_confirmation_paths
from metis.engine.reachability.builder import (
    TreeSitterReachabilityGraphBuilder,
)
from metis.engine.reachability.c_family import (
    CFamilyTreeSitterExtractor,
)
from metis.engine.reachability.file_focus import FileFocusBuilder
from metis.engine.reachability.finding_paths import FindingPathAnnotator
from metis.engine.reachability import VulnerabilityFinding


def test_confidence_score_matches_review_schema():
    assert _confidence_score("high") == 0.95
    assert _confidence_score("medium") == 0.75
    assert _confidence_score("low") == 0.55
    assert _confidence_score("0.81") == 0.81
    assert _confidence_score(2.0) == 1.0


def test_treesitter_builder_uses_installed_parser_runtime(tmp_path):
    source = tmp_path / "main.c"
    source.write_text(
        "void foo(void) {}\nint main(void) { foo(); return 0; }\n",
        encoding="utf-8",
    )

    events = []
    graph = TreeSitterReachabilityGraphBuilder().build(
        [str(source)], str(tmp_path), progress_callback=events.append
    )

    done = [event for event in events if event["event"] == "treesitter_graph_done"]
    assert done and not done[0]["errors"]
    assert graph.node_count() == 2
    assert graph.get_node("main.c::main").resolved_calls == ["main.c::foo"]


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


class _Tree:
    def __init__(self, root):
        self._root = root

    def root_node(self):
        return self._root


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
    import metis.engine.analysis.c_family_ast as c_family_ast
    import metis.engine.reachability.c_family as c_family

    def fake_identifier(node, _source):
        return getattr(node, "text", "") if node else ""

    monkeypatch.setattr(c_family, "_node_text", lambda node, _source: node.text)
    monkeypatch.setattr(c_family, "_identifier_from_node", fake_identifier)
    monkeypatch.setattr(c_family_ast, "_identifier_from_node", fake_identifier)

    foo_call_ident = _Node("identifier", text="foo", line=3)
    foo_call = _Node("call_expression", line=3, fields={"function": foo_call_ident})
    main_def = _Node(
        "function_definition",
        text="int main(int argc, char **argv) { foo(argv[1]); }",
        line=1,
        children=[foo_call],
        fields={"declarator": _Node("function_declarator", text="main", line=1)},
    )

    memcpy_ident = _Node("identifier", text="memcpy", line=8)
    memcpy_call = _Node("call_expression", line=8, fields={"function": memcpy_ident})
    foo_def = _Node(
        "function_definition",
        text="void foo(char *src) { char dst[8]; memcpy(dst, src, 64); }",
        line=6,
        children=[memcpy_call],
        fields={"declarator": _Node("function_declarator", text="foo", line=6)},
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


def test_source_rooted_tracer_keeps_maximal_non_sink_paths():
    graph = ReachabilityGraph()
    for node in [
        _fn("src/main.c::main", "src/main.c", "main", 1, source=True, calls=["a"]),
        _fn("src/a.c::a", "src/a.c", "a", 10, calls=["d"]),
        _fn("src/d.c::d", "src/d.c", "d", 20, sink=True, calls=["e"]),
        _fn("src/e.c::e", "src/e.c", "e", 30),
    ]:
        graph.add_node(node)
    graph.resolve_all_calls()

    paths = SourceRootedPathTracer(graph).find_all_paths()

    assert [path.path for path in paths] == [
        [
            "src/main.c::main",
            "src/a.c::a",
            "src/d.c::d",
            "src/e.c::e",
        ]
    ]
    assert paths[0].sink == "src/e.c::e"
    assert paths[0].sink_type == "reachable_endpoint"


def test_source_rooted_tracer_omits_recursive_loop():
    graph = ReachabilityGraph()
    for node in [
        _fn("src/main.c::main", "src/main.c", "main", 1, source=True, calls=["a"]),
        _fn("src/a.c::a", "src/a.c", "a", 10, calls=["b"]),
        _fn("src/b.c::b", "src/b.c", "b", 20, calls=["a"]),
    ]:
        graph.add_node(node)
    graph.resolve_all_calls()

    paths = SourceRootedPathTracer(graph).find_all_paths()

    assert [path.path for path in paths] == [
        [
            "src/main.c::main",
            "src/a.c::a",
            "src/b.c::b",
        ]
    ]


def test_reachability_service_auto_caps_confirmation_paths():
    graph = ReachabilityGraph()
    source = _fn("src/main.c::main", "src/main.c", "main", 1, source=True)
    graph.add_node(source)
    for idx in range(80):
        source.calls.append(f"leaf_{idx}")
        graph.add_node(
            _fn(
                f"src/leaf_{idx}.c::leaf_{idx}",
                f"src/leaf_{idx}.c",
                f"leaf_{idx}",
                idx + 2,
                sink=idx % 3 == 0,
            )
        )
    graph.resolve_all_calls()
    paths = SourceRootedPathTracer(graph).find_all_paths()

    selected = select_confirmation_paths(paths, graph)
    selected_endpoints = {path.sink for path in selected}

    assert len(paths) == 80
    assert len(selected) == 12
    assert len(selected_endpoints) == 12
    assert any(graph.get_node(path.sink).is_sink for path in selected)


def _deep_chain(depth, leaf):
    node = leaf
    for idx in range(depth):
        node = _Node(f"wrapper_{idx}", children=[node])
    return node


def test_c_family_extractor_handles_deep_trees_without_recursion(monkeypatch):
    import metis.engine.analysis.c_family_ast as c_family_ast
    import metis.engine.reachability.c_family as c_family

    def fake_identifier(node, _source):
        return getattr(node, "text", "") if node else ""

    monkeypatch.setattr(c_family, "_node_text", lambda node, _source: node.text)
    monkeypatch.setattr(c_family, "_identifier_from_node", fake_identifier)
    monkeypatch.setattr(c_family_ast, "_identifier_from_node", fake_identifier)

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
    ident = _Node("identifier", start_byte=0, end_byte=9)
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


def _finding(
    vtype,
    file_path,
    function,
    line,
    description,
    root_cause,
    *,
    canonical_key="",
    path=None,
):
    return VulnerabilityFinding(
        id=f"{vtype}-{line}",
        vulnerability_type=vtype,
        severity="high",
        confidence="high",
        source_function=function,
        source_file=file_path,
        source_line=line,
        sink_function=function,
        sink_file=file_path,
        sink_line=line,
        path=list(path or [function]),
        description=description,
        root_cause=root_cause,
        evidence=root_cause,
        analysis_type="test",
        primary_file=file_path,
        primary_function=function,
        primary_line=line,
        canonical_key=canonical_key,
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

    finding = _finding(
        "integer_overflow",
        "src/review.c",
        "src/review.c::helper",
        30,
        "helper has unchecked arithmetic",
        "helper has unchecked arithmetic",
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

    finding = _finding(
        "other",
        "src/other.c",
        "src/other.c::other",
        10,
        "other-file finding",
        "other-file finding",
    )

    [annotated] = FindingPathAnnotator(graph, "src/review.c").annotate([finding])

    assert annotated is finding


def test_deduplicator_merges_same_canonical_key_across_paths():
    key = "src/task.c:src/task.c::task_import:out_of_bounds:unterminated_title"
    findings = [
        _finding(
            "missing_bounds_check",
            "src/task.c",
            "src/task.c::task_import",
            63,
            "Import passes a length-delimited title to task_create.",
            "title import buffer not terminated before task_create strlen",
            canonical_key=key,
            path=["src/api.c::dispatch", "src/task.c::task_import"],
        ),
        _finding(
            "out_of_bounds",
            "src/task.c",
            "src/task.c::task_import",
            64,
            "The same title slice can be read past its end.",
            "unterminated title reaches strlen",
            canonical_key=key,
            path=["src/io.c::read_task", "src/task.c::task_import"],
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 1
    assert len(deduped) == 1
    assert (
        deduped[0].canonical_key
        == "src/task.c:src/task.c::task_import:out_of_bounds:unterminated_title"
    )


def test_canonical_fields_build_deterministic_key_from_root_cause_id():
    primary_file, primary_function, primary_line, canonical_key = _canonical_fields(
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

    assert primary_file == "src/task.c"
    assert primary_function == "src/task.c::task_import"
    assert primary_line == 64
    assert (
        canonical_key
        == "src/task.c:src/task.c::task_import:missing_bounds_check:unterminated_title"
    )


def test_deduplicator_normalizes_raw_canonical_key_to_structured_identity():
    findings = [
        _finding(
            "missing_bounds_check",
            "src/task.c",
            "src/task.c::task_import",
            63,
            "Import passes a length-delimited title to task_create.",
            "title import buffer not terminated before task_create strlen",
            canonical_key="src/task.c:src/task.c::task_import:out_of_bounds:unterminated_title",
        ),
        _finding(
            "out_of_bounds",
            "src/task.c",
            "src/task.c::task_import",
            64,
            "The same title slice can be read past its end.",
            "unterminated title reaches strlen",
            canonical_key="task_import:memory_bounds:unterminated_title",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 1
    assert len(deduped) == 1


def test_deduplicator_prefers_specific_primary_location_for_same_root():
    key = "src/dispatch.c:src/dispatch.c::handle_reset:missing_auth:reset_missing_permission"
    vague = _finding(
        "missing_auth",
        "src/dispatch.c",
        "src/dispatch.c::handle_reset",
        0,
        "Reset is missing an authorization check.",
        "",
        canonical_key=key,
        path=["src/dispatch.c::handle_reset"],
    )
    vague.primary_line = 0
    vague.evidence = ""
    vague.mitigation = ""
    specific = _finding(
        "missing_auth",
        "src/dispatch.c",
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

    deduped, total, removed = Deduplicator.deduplicate([vague, specific])

    assert total == 2
    assert removed == 1
    assert deduped == [specific]


def test_deduplicator_keeps_different_canonical_keys_in_same_location():
    findings = [
        _finding(
            "missing_auth",
            "src/dispatch.c",
            "src/dispatch.c::handle_task_update",
            80,
            "Task update treats auth_get_level as a boolean.",
            "auth level boolean gate for task update",
            canonical_key="src/dispatch.c:src/dispatch.c::handle_task_update:missing_auth:boolean_gate",
        ),
        _finding(
            "missing_auth",
            "src/dispatch.c",
            "src/dispatch.c::handle_task_update",
            82,
            "Task update does not verify that the session owns the task.",
            "missing owner check before task update",
            canonical_key="src/dispatch.c:src/dispatch.c::handle_task_update:missing_auth:owner_check",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 0
    assert len(deduped) == 2


def test_deduplicator_falls_back_to_exact_type_when_key_missing():
    findings = [
        _finding(
            "array_index_size_mismatch",
            "src/dispatch.c",
            "src/dispatch.c::dispatch",
            198,
            "priority_counts is indexed with msg.flags & 0x0F.",
            "masked array index can exceed priority_counts length",
        ),
        _finding(
            "array_oob",
            "src/dispatch.c",
            "src/dispatch.c::dispatch",
            199,
            "The priority_counts index allows values 0 through 15.",
            "0x0F masked index can exceed the array bounds",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 0
    assert len(deduped) == 2
    assert [finding.vulnerability_type for finding in deduped] == [
        "array_index_size_mismatch",
        "array_oob",
    ]


def test_deduplicator_caps_per_function_type_after_canonical_merge():
    findings = [
        _finding(
            "missing_auth",
            "src/dispatch.c",
            "src/dispatch.c::handle_task_update",
            80 + index,
            f"Missing authorization check {index}.",
            f"missing authorization check {index}",
            canonical_key=f"src/dispatch.c:src/dispatch.c::handle_task_update:missing_auth:check_{index}",
            path=[f"src/api.c::entry_{index}", "src/dispatch.c::handle_task_update"],
        )
        for index in range(4)
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings, max_per_sink=2)

    assert total == 4
    assert removed == 2
    assert len(deduped) == 2
