# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace

import pytest

from metis.engine.analysis.c_family_ast import CFamilyAstMixin
from metis.engine.reachability import (
    Deduplicator,
    FunctionNode,
    ReachabilityGraph,
    SourceRootedPathTracer,
    VulnerabilityFinding,
)
from metis.engine.reachability.c_family import CFamilyTreeSitterExtractor
from metis.engine.reachability.file_focus import FileFocusBuilder
from metis.engine.reachability.finding_identity import _canonical_fields
from metis.engine.reachability.finding_paths import FindingPathAnnotator
from metis.engine.reachability.graph_cache import ReachabilityGraphCache
from metis.engine.reachability.graph_utils import select_confirmation_paths
from metis.plugins.c_plugin import CPlugin
from test_c_family_analyzer import _Node, _Runtime


def _reachability_cache(codebase_path):
    plugin = CPlugin(plugin_config={"plugins": {}})
    return ReachabilityGraphCache(
        SimpleNamespace(codebase_path=codebase_path),
        SimpleNamespace(
            get_code_files=lambda: [], get_plugin_for_path=lambda _path: plugin
        ),
    )


def _patch_ids(monkeypatch):
    import metis.engine.analysis.c_family_ast as c_family_ast
    import metis.engine.reachability.c_family as c_family

    def fake_identifier(node, _source):
        return getattr(node, "text", "") if node else ""

    monkeypatch.setattr(c_family, "_node_text", lambda node, _source: node.text)
    monkeypatch.setattr(c_family, "_identifier_from_node", fake_identifier)
    monkeypatch.setattr(c_family_ast, "_identifier_from_node", fake_identifier)


def _call(name, line=1):
    ident = _Node("identifier", text=name, line=line)
    return _Node("call_expression", line=line, fields={"function": ident})


def _func(name, text, line, *, child=None):
    children = [child] if child else []
    return _Node(
        "function_definition",
        text=text,
        line=line,
        children=children,
        fields={"declarator": _Node("function_declarator", text=name, line=line)},
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
        source,
        sink,
        calls=list(calls or []),
        sink_type="other" if sink else "",
    )


def _graph(*nodes):
    graph = ReachabilityGraph()
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


def test_reachability_cache_uses_installed_parser_runtime(tmp_path):
    source = tmp_path / "main.c"
    source.write_text(
        "void foo(void) {}\nint main(void) { foo(); return 0; }\n",
        encoding="utf-8",
    )
    events = []
    graph = _reachability_cache(str(tmp_path)).build_graph(
        [str(source)], progress_callback=events.append
    )
    done = [event for event in events if event["event"] == "treesitter_graph_done"]
    assert done and not done[0]["errors"]
    assert graph.node_count() == 2
    assert graph.get_node("main.c::main").resolved_calls == ["main.c::foo"]


def test_reachability_cache_extracts_reachability_graph(monkeypatch):
    _patch_ids(monkeypatch)
    root = _Node(
        "translation_unit",
        children=[
            _func(
                "main",
                "int main(int argc, char **argv) { foo(argv[1]); }",
                1,
                child=_call("foo", 3),
            ),
            _func(
                "foo",
                "void foo(char *src) { char dst[8]; memcpy(dst, src, 64); }",
                6,
                child=_call("memcpy", 8),
            ),
        ],
    )
    cache = _reachability_cache(".")
    cache._extractor._runtimes = {"c": _Runtime(root)}

    graph = cache.build_graph(["main.c"])

    assert graph.node_count() == 2
    assert graph.get_node("main.c::main").is_source is True
    assert graph.get_node("main.c::foo").is_sink is True
    assert graph.get_node("main.c::foo").sink_type == "buffer_overflow"
    assert graph.get_node("main.c::main").resolved_calls == ["main.c::foo"]


def test_reachability_cache_keeps_configured_annotations_isolated():
    cache = _reachability_cache(".")
    cache._base_graph = _graph(
        _fn("src/main.c::main", 1, calls=["entry"]),
        _fn("src/api.c::entry", 10),
    )

    plain = cache.ensure_graph()
    configured = cache.ensure_graph(
        source_functions=[{"name": "entry", "reason": "test source"}]
    )

    assert plain.get_node("src/api.c::entry").is_source is False
    assert configured.get_node("src/api.c::entry").is_source is True
    assert cache.ensure_graph() is plain
    assert (
        cache.ensure_graph(
            source_functions=[{"name": "entry", "reason": "test source"}]
        )
        is configured
    )


@pytest.mark.parametrize(
    ("nodes", "expected", "sink", "sink_type"),
    [
        (
            [
                _fn("src/main.c::main", 1, source=True, calls=["a"]),
                _fn("src/a.c::a", 10, calls=["d"]),
                _fn("src/d.c::d", 20, sink=True, calls=["e"]),
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


def test_c_family_extractor_handles_deep_trees_without_recursion(monkeypatch):
    _patch_ids(monkeypatch)
    extractor = object.__new__(CFamilyTreeSitterExtractor)
    deep_fn = _func(
        "deep_fn",
        "void deep_fn(void) { memcpy(dst, src, len); }",
        1,
        child=_deep_chain(1500, _call("memcpy", 1502)),
    )
    nodes = extractor._collect_function_nodes(_deep_chain(1500, deep_fn), b"", "deep.c")

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

    assert [node.name for node in nodes] == ["deep_fn"]
    assert nodes[0].calls == ["memcpy"]
    assert refs == {"deep_open"}
    assert len(globals_) == 1


def test_c_family_ast_helpers_handle_deep_trees_without_recursion():
    ident = _Node("identifier", start_byte=0, end_byte=9)
    root = _deep_chain(
        1500,
        _Node("call_expression", children=[ident], fields={"function": ident}),
    )
    harness = CFamilyAstMixin()

    nodes = harness._index_tree(root)
    calls = harness._collect_calls(root, b"deep_call")
    refs = harness._collect_references(root, b"deep_call")

    assert len(nodes) == 1502
    assert calls["deep_call"][0].symbol == "deep_call"
    assert refs["deep_call"][0].symbol == "deep_call"


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
