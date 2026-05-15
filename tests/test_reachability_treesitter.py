# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.analysis.c_family_analyzer_common import _identifier_from_node
from metis.engine.analysis.c_family_ast import CFamilyAstMixin
from metis.engine.reachability_common import (
    Deduplicator,
    FunctionNode,
    ReachabilityGraph,
    SourceRootedPathTracer,
)
from metis.engine.reachability_common.finding_normalization import _confidence_score
from metis.engine.reachability_service_modular.builder import (
    TreeSitterReachabilityGraphBuilder,
)
from metis.engine.reachability_service_modular.c_family import (
    CFamilyTreeSitterExtractor,
)
from metis.engine.reachability_service_modular.file_focus import FileFocusBuilder
from metis.engine.reachability_service_modular.finding_paths import FindingPathAnnotator
from metis.engine.reachability_service_modular.service import (
    TreeSitterReachabilityService,
)
from metis.engine.reachability_common import VulnerabilityFinding


def test_confidence_score_matches_review_schema():
    assert _confidence_score("high") == 0.95
    assert _confidence_score("medium") == 0.75
    assert _confidence_score("low") == 0.55
    assert _confidence_score("0.81") == 0.81
    assert _confidence_score(2.0) == 1.0


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
    service = object.__new__(TreeSitterReachabilityService)

    selected = service.select_confirmation_paths(paths, graph)
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


def _finding(vtype, file_path, function, line, description, root_cause):
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
        path=[function],
        description=description,
        root_cause=root_cause,
        evidence=root_cause,
        analysis_type="test",
        primary_file=file_path,
        primary_function=function,
        primary_line=line,
        canonical_key=f"{file_path}:{function}:{vtype}:{line}",
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


def test_deduplicator_merges_auth_variants_for_same_gate():
    findings = [
        _finding(
            "permission_mismatch",
            "src/dispatch.c",
            "src/dispatch.c::handle_proj_create",
            108,
            "Project creation checks RES_TASK instead of a project permission.",
            "project create permission resource mismatch",
        ),
        _finding(
            "auth_logic_error",
            "src/dispatch.c",
            "src/dispatch.c::handle_proj_create",
            108,
            "Authorization is gated by treating auth_get_level as a boolean.",
            "auth level boolean project create permission",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 1
    assert len(deduped) == 1


def test_deduplicator_merges_refcount_release_variants_for_same_line():
    findings = [
        _finding(
            "accounting_drift",
            "src/dispatch.c",
            "src/dispatch.c::handle_stats",
            181,
            "The stats handler increments a refcount once but decrements twice.",
            "store_ref followed by store_unref store_unref on same entry",
        ),
        _finding(
            "double_free",
            "src/dispatch.c",
            "src/dispatch.c::handle_stats",
            181,
            "The same store entry is unreferenced twice after one explicit ref.",
            "duplicate store_unref releases same refcounted entry",
        ),
        _finding(
            "refcount_imbalance",
            "src/dispatch.c",
            "src/dispatch.c::handle_stats",
            181,
            "One acquired reference is released twice.",
            "unmatched store_ref store_unref calls decrement refcount too far",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 3
    assert removed == 2
    assert len(deduped) == 1


def test_deduplicator_merges_callback_lifecycle_variants_in_same_file():
    findings = [
        _finding(
            "teardown_race",
            "src/session.c",
            "src/session.c::session_close",
            50,
            "Session teardown frees callback ctx without notify unregister.",
            "notify callback register ctx session free without unregister",
        ),
        _finding(
            "state_order",
            "src/session.c",
            "src/session.c::session_close",
            50,
            "notify_fire can invoke on_session_event with a freed session pointer.",
            "callback ctx not unregistered before session free notify_fire",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 1
    assert len(deduped) == 1


def test_deduplicator_merges_common_model_aliases():
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
            198,
            "The priority_counts index allows values 0 through 15.",
            "0x0F masked index can exceed the array bounds",
        ),
        _finding(
            "integer_overflow_allocation",
            "src/store.c",
            "src/store.c::store_grow",
            18,
            "store_grow computes new_cap * sizeof(store_entry_t).",
            "unchecked capacity multiplication can wrap allocation size",
        ),
        _finding(
            "integer_overflow",
            "src/store.c",
            "src/store.c::store_grow",
            18,
            "The grow size calculation can overflow before realloc.",
            "capacity multiplication can wrap allocation size before realloc",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 4
    assert removed == 2
    assert len(deduped) == 2


def test_deduplicator_merges_authorization_bypass_aliases():
    findings = [
        _finding(
            "missing_auth",
            "src/dispatch.c",
            "src/dispatch.c::handle_proj_add",
            130,
            "Project add ignores the session and performs no permission check.",
            "session ignored project add authorization missing owner permission",
        ),
        _finding(
            "authorization_bypass",
            "src/dispatch.c",
            "src/dispatch.c::handle_proj_add",
            136,
            "The project-add handler performs the operation without authentication.",
            "project add session ignored authorization bypass owner check missing",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 1
    assert len(deduped) == 1
    assert deduped[0].vulnerability_type == "missing_auth"


def test_deduplicator_merges_auth_helper_reports_across_callers():
    findings = [
        _finding(
            "permission_mismatch",
            "src/auth.c",
            "src/auth.c::auth_get_level",
            29,
            "auth_get_level ignores the requested resource and returns a global level.",
            "auth get level ignores resource permission; callers use auth_get_level boolean checks",
        ),
        _finding(
            "boolean_coercion",
            "src/dispatch.c",
            "src/dispatch.c::handle_task_create",
            41,
            "Task creation treats auth_get_level as a boolean.",
            "auth get level boolean permission gate for task create",
        ),
        _finding(
            "boolean_coercion",
            "src/dispatch.c",
            "src/dispatch.c::handle_task_update",
            80,
            "Task update treats auth_get_level as a boolean.",
            "auth get level boolean permission gate for task update",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 3
    assert removed == 2
    assert len(deduped) == 1
    assert deduped[0].vulnerability_type == "permission_mismatch"


def test_deduplicator_keeps_distinct_owner_check_and_boolean_gate():
    findings = [
        _finding(
            "boolean_coercion",
            "src/dispatch.c",
            "src/dispatch.c::handle_task_update",
            80,
            "Task update treats auth_get_level as a boolean.",
            "auth get level boolean permission gate for task update",
        ),
        _finding(
            "authorization_bypass",
            "src/dispatch.c",
            "src/dispatch.c::handle_task_update",
            90,
            "Task update does not verify that the session owns the task.",
            "missing task owner check before task_set_title update",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 0
    assert len(deduped) == 2


def test_deduplicator_merges_format_string_helper_and_callsite():
    findings = [
        _finding(
            "format_string",
            "src/util.c",
            "src/util.c::util_log",
            35,
            "util_log passes msg directly as the vprintf format string.",
            "caller controlled msg used as printf format string in vprintf",
        ),
        _finding(
            "info_leak",
            "src/dispatch.c",
            "src/dispatch.c::handle_task_get",
            74,
            "A task title is passed directly to util_log as the format string.",
            "task title util_log vprintf format specifier can disclose stack data",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 1
    assert len(deduped) == 1
    assert deduped[0].vulnerability_type == "format_string"


def test_deduplicator_merges_unterminated_title_variants():
    findings = [
        _finding(
            "missing_bounds_check",
            "src/task.c",
            "src/task.c::task_import",
            63,
            "Import passes a length-delimited title to task_create without a NUL terminator.",
            "title import buffer not NUL terminated before task_create strlen string",
        ),
        _finding(
            "out_of_bounds",
            "src/task.c",
            "src/task.c::task_create",
            17,
            "task_create calls strlen on attacker-controlled title slices.",
            "task_create strlen title can read past non-terminated import buffer",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 1
    assert len(deduped) == 1
    assert deduped[0].vulnerability_type == "out_of_bounds"


def test_deduplicator_merges_session_get_lifetime_variants():
    findings = [
        _finding(
            "refcount_imbalance",
            "src/session.c",
            "src/session.c::session_get",
            32,
            "session_get returns a session pointer without acquiring a lifetime reference.",
            "session_get no refcount lifetime acquire; fresh session used across maintenance sweep free",
        ),
        _finding(
            "use_after_free",
            "src/dispatch.c",
            "src/dispatch.c::handle_task_get",
            58,
            "handle_task_get caches a session pointer across maintenance and dereferences it.",
            "fresh session pointer from session_get crosses session_run_maintenance session_sweep expire free",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 1
    assert len(deduped) == 1
    assert deduped[0].vulnerability_type == "use_after_free"


def test_deduplicator_merges_task_delete_project_membership_variants():
    findings = [
        _finding(
            "accounting_drift",
            "src/task.c",
            "src/task.c::task_delete",
            45,
            "Deleting a task does not decrement the project's member_count.",
            "project_add_task increments member_count but task_delete remove does not clear project member count",
        ),
        _finding(
            "stale_state_after_disable",
            "src/task.c",
            "src/task.c::task_delete",
            45,
            "Deleting a task leaves project members and cached_entries pointing at stale state.",
            "task_delete removes store entry without clearing project members cached entries",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 1
    assert len(deduped) == 1


def test_deduplicator_merges_same_expression_null_and_bounds_variants():
    findings = [
        _finding(
            "missing_bounds_check",
            "src/auth.c",
            "src/auth.c::auth_verify_session",
            42,
            "Copies identity into a fixed-size buffer without checking length.",
            "char identity buffer memcpy full strlen length unchecked",
        ),
        _finding(
            "null_deref",
            "src/auth.c",
            "src/auth.c::auth_verify_session",
            42,
            "user_get_identity can return NULL before strlen(full).",
            "full from user_get_identity unchecked before strlen memcpy identity",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 1
    assert len(deduped) == 1


def test_deduplicator_merges_same_expression_type_and_size_variants():
    findings = [
        _finding(
            "type_confusion",
            "src/dispatch.c",
            "src/dispatch.c::handle_stats",
            173,
            "store_get data is cast to task_t without checking the type tag.",
            "store_get admin_task data cast task_t no type tag validation",
        ),
        _finding(
            "missing_bounds_check",
            "src/dispatch.c",
            "src/dispatch.c::handle_stats",
            174,
            "The returned store size is ignored before strlen(t->title).",
            "store_get size ignored data cast task_t title strlen",
        ),
    ]

    deduped, total, removed = Deduplicator.deduplicate(findings)

    assert total == 2
    assert removed == 1
    assert len(deduped) == 1
