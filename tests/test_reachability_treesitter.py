# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import replace
from functools import partial
from types import SimpleNamespace

import pytest

from metis.engine.reachability import (
    Deduplicator,
    FunctionNode,
    ReachabilityGraph,
    SourceRootedPathTracer,
    VulnerabilityFinding,
)
from metis.engine.reachability.c_family_ast import CFamilyAstMixin
from metis.engine.reachability.c_family import CFamilyTreeSitterExtractor
from metis.engine.reachability.file_focus import FileFocusBuilder
from metis.engine.reachability.finding_finalizer import FindingFinalizer
from metis.engine.reachability.finding_identity import _canonical_fields
from metis.engine.reachability.finding_paths import FindingPathAnnotator
from metis.engine.reachability.graph_cache import ReachabilityGraphCache
from metis.engine.reachability.graph_utils import (
    _build_reverse_edges,
    _node_sort_key,
    select_confirmation_paths,
)
from metis.engine.reachability.options import ReachabilityReviewOptions
from metis.engine.reachability.service import TreeSitterReachabilityService
from metis.engine.llm_runner import JsonPromptRunner
from metis.plugins.c_plugin import CPlugin


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
    def __init__(self, root):
        self._root = root
        self.is_available = True
        self.init_error = ""

    def parse_file(self, _codebase_path, _rel_path):
        return _Parsed(self._root)


def _reachability_cache(codebase_path):
    plugin = CPlugin(plugin_config={"plugins": {}})
    return ReachabilityGraphCache(
        SimpleNamespace(codebase_path=codebase_path),
        SimpleNamespace(
            get_code_files=lambda: [], get_plugin_for_path=lambda _path: plugin
        ),
    )


def _patch_ids(monkeypatch):
    import metis.engine.reachability.c_family_ast as c_family_ast
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


class _BoundedGraphNodes(dict):
    def __init__(self, nodes, *, visits, lookups):
        super().__init__(nodes)
        self._visits = visits
        self._lookups = lookups

    def values(self):
        for node in super().values():
            self._visits -= 1
            assert self._visits >= 0, "annotation repeatedly traverses the whole graph"
            yield node

    def get(self, name, default=None):
        self._lookups -= 1
        assert self._lookups >= 0, "annotation explores routes instead of unique nodes"
        return super().get(name, default)


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


def test_file_focus_uses_deterministic_shortest_source_path():
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

    assert [path.path for path in focus.incoming_paths] == [
        ["src/main.c::main", "src/a.c::wrap_a", "src/review.c::reviewed"]
    ]


def test_file_focus_bounds_repeated_paths(monkeypatch):
    layers = (
        [["start"]]
        + [[f"node_{depth}_{branch}" for branch in range(3)] for depth in range(8)]
        + [["end"]]
    )
    graph = _graph(
        *[
            _fn(
                f"graph.c::{name}",
                depth + 1,
                calls=layers[depth + 1] if depth + 1 < len(layers) else [],
            )
            for depth, names in enumerate(layers)
            for name in names
        ]
    )
    builder = FileFocusBuilder(graph, max_path_length=len(layers))
    target = graph.get_node("graph.c::end")
    get_node = graph.get_node
    lookups = 0

    def bounded_get_node(name):
        nonlocal lookups
        lookups += 1
        assert lookups <= 1000, "path search repeatedly expands the same nodes"
        return get_node(name)

    monkeypatch.setattr(graph, "get_node", bounded_get_node)

    assert builder._incoming_paths_for_target(target) == []


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

    [annotated] = FindingPathAnnotator(
        graph,
        "src/review.c",
        reverse_edges=_build_reverse_edges(graph, partial(_node_sort_key, graph)),
    ).annotate([finding])

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


def test_finding_path_annotator_respects_empty_reverse_index():
    graph = _graph(
        _fn("source.c::entry", 1, source=True, calls=["target"]),
        _fn("review.c::target", 1),
    )
    graph.nodes = _BoundedGraphNodes(graph.nodes, visits=0, lookups=1)
    annotator = FindingPathAnnotator(graph, "review.c", reverse_edges={})

    assert annotator._best_source_path_to("review.c::target") == []


def test_finding_finalizer_bounds_index_work_across_files():
    targets = [_fn(f"src/file_{i}.c::target_{i}", i + 2) for i in range(24)]
    source = _fn("src/main.c::entry", 1, source=True, calls=[n.name for n in targets])
    graph = _graph(source, *targets)
    findings = [
        _finding(
            "integer_overflow", node.unique_name, node.line_number, "issue", "cause"
        )
        for node in targets
    ]
    graph.nodes = _BoundedGraphNodes(
        graph.nodes,
        visits=graph.node_count(),
        lookups=graph.edge_count() + 4 * len(findings),
    )

    annotated = FindingFinalizer(".").annotate_findings_with_source_paths(
        findings, graph
    )

    assert annotated == [
        replace(
            finding,
            source_function=source.unique_name,
            source_file=source.file_path,
            source_line=source.line_number,
            path=[source.unique_name, finding.sink_function],
        )
        for finding in findings
    ]
    assert [finding.path for finding in findings] == [
        [node.unique_name] for node in targets
    ]


def test_finding_finalizer_bounds_unreachable_cyclic_search():
    layers = [[f"node_{depth}_{branch}" for branch in range(3)] for depth in range(8)]
    graph = _graph(
        _fn("cycle.c::left", 1, calls=["right", *layers[0]]),
        _fn("cycle.c::right", 2, calls=["left", *layers[0]]),
        *[
            _fn(
                f"layer_{depth}.c::{name}",
                branch + 1,
                calls=layers[depth + 1] if depth + 1 < len(layers) else ["target"],
            )
            for depth, names in enumerate(layers)
            for branch, name in enumerate(names)
        ],
        _fn("review.c::target", 1),
    )
    finding = _finding("other", "review.c::target", 1, "unreachable issue", "cause")
    graph.nodes = _BoundedGraphNodes(
        graph.nodes,
        visits=graph.node_count(),
        lookups=graph.edge_count() + graph.node_count() + 2,
    )

    [annotated] = FindingFinalizer(".").annotate_findings_with_source_paths(
        [finding], graph
    )

    assert annotated is finding
    assert annotated.path == ["review.c::target"]


@pytest.mark.parametrize("target_file", ["", "review.c"])
def test_finding_finalizer_skips_graph_work_without_findings(target_file):
    graph = _graph(_fn("review.c::entry", 1, source=True))
    graph.nodes = _BoundedGraphNodes(graph.nodes, visits=0, lookups=0)
    finalizer = FindingFinalizer(".")

    assert finalizer.annotate_findings_with_source_paths([], graph) == []
    assert finalizer.finalize(
        [], graph, options=ReachabilityReviewOptions(), target_file=target_file
    ) == ([], 0, 0)


def test_finding_finalizer_skips_graph_work_without_target_file():
    graph = _graph(_fn("review.c::entry", 1, source=True))
    graph.nodes = _BoundedGraphNodes(graph.nodes, visits=0, lookups=0)
    finding = _finding("other", "missing", 1, "issue", "cause")
    finding.primary_file = finding.sink_file = finding.source_file = ""

    [annotated] = FindingFinalizer(".").annotate_findings_with_source_paths(
        [finding], graph
    )

    assert annotated is finding
    assert annotated.path == ["missing"]


@pytest.mark.parametrize(
    ("target", "limit", "expected"),
    [
        ("missing", 3, []),
        ("z_source.c::source_z", 1, ["z_source.c::source_z"]),
        ("review.c::target", 1, []),
        ("review.c::target", 2, []),
        (
            "review.c::target",
            3,
            ["z_source.c::source_z", "a.c::first", "review.c::target"],
        ),
    ],
)
def test_finding_path_search_preserves_sorted_bfs_and_node_depth(
    target, limit, expected
):
    graph = _graph(
        _fn("a_source.c::source_a", 1, source=True, calls=["last"]),
        _fn("z_source.c::source_z", 1, source=True, calls=["first"]),
        _fn("z.c::last", 1, calls=["target"]),
        _fn("a.c::first", 1, calls=["target"]),
        _fn("review.c::target", 1),
    )
    reverse_edges = _build_reverse_edges(graph, partial(_node_sort_key, graph))
    reverse_edges["review.c::target"].insert(0, "missing.c::caller")
    annotator = FindingPathAnnotator(
        graph, "review.c", reverse_edges=reverse_edges, max_path_length=limit
    )

    assert annotator._best_source_path_to(target) == expected


@pytest.mark.parametrize(
    "existing_path", [["target"], ["original", "longer", "target"]]
)
def test_finding_finalizer_preserves_lookup_and_metadata(existing_path):
    graph = _graph(
        _fn("src/a.c::target", 1, source=True),
        _fn("src/source.c::entry", 2, source=True, calls=["target"]),
        _fn("src/review.c::target", 3),
    )
    graph.get_node("src/source.c::entry").resolved_calls = ["src/review.c::target"]
    finding = _finding(
        "integer_overflow",
        "src/review.c::target",
        9,
        "issue",
        "cause",
        path=existing_path,
    )
    finding.primary_file = "src\\review.c"
    finding.primary_function = finding.sink_function = finding.source_function = (
        "target"
    )
    finding.primary_anchor = {"start_line": 8, "end_line": 9, "symbol": "target"}
    finding.mitigation = "check the arithmetic"
    finding.cwe = "CWE-190"

    [annotated], total, removed = FindingFinalizer(".").finalize(
        [finding],
        graph,
        options=ReachabilityReviewOptions(),
        target_file="src/review.c",
    )

    assert (total, removed) == (1, 0)
    if len(existing_path) > 2:
        assert annotated is finding
    else:
        assert annotated == replace(
            finding,
            source_function="src/source.c::entry",
            source_file="src/source.c",
            source_line=2,
            sink_function="src/review.c::target",
            sink_file="src/review.c",
            sink_line=3,
            path=["src/source.c::entry", "src/review.c::target"],
        )


@pytest.fixture
def offline_reachability_service(tmp_path, monkeypatch):
    (tmp_path / "main.c").write_text(
        "void first(void) { root(); custom_copy(); }\n"
        "void second(void) {}\n"
        "void root(void) { first(); second(); }\n",
        encoding="utf-8",
    )
    (tmp_path / "excluded.c").write_text("void excluded(void) {}\n", encoding="utf-8")
    (tmp_path / "notes.py").write_text("def unrelated(): pass\n", encoding="utf-8")
    plugin = CPlugin(plugin_config={"plugins": {}})
    repository = SimpleNamespace(
        get_code_files=lambda: ["main.c", "excluded.c", "notes.py"],
        get_plugin_for_path=lambda _path: plugin,
        supports_reachability_file=lambda path: path.endswith(".c"),
    )

    def model_response(_runner, request):
        if "candidate_findings" in request.variables:
            return {"groups": []}
        if "paths_section" in request.variables:
            return {
                "findings": [
                    {
                        "path_index": 0,
                        "is_vulnerable": True,
                        "vulnerability_type": "integer_overflow",
                        "description": "confirmed path issue",
                        "root_cause": "unchecked path arithmetic",
                        "confidence": 0.95,
                    }
                ]
            }
        if "allowed_analysis_types" in request.variables:
            return {
                "findings": [
                    {
                        "analysis_type": "semantic",
                        "function_name": "first",
                        "vulnerability_type": "buffer_overflow",
                        "description": "graph lens issue",
                        "root_cause": "unchecked custom copy",
                        "confidence": 0.95,
                    }
                ]
            }
        return {"findings": []}

    monkeypatch.setattr(JsonPromptRunner, "invoke", model_response)
    return TreeSitterReachabilityService(
        SimpleNamespace(codebase_path=str(tmp_path), llama_query_model="offline"),
        repository,
        None,
        None,
    )


@pytest.mark.parametrize(
    ("confirm_paths", "max_paths", "confirmed_targets"),
    [
        (False, 0, []),
        (False, 1, []),
        (True, 0, ["main.c::first", "main.c::second"]),
        (True, 1, ["main.c::first"]),
    ],
)
def test_review_codebase_confirmation_policy_preserves_lens_findings(
    offline_reachability_service,
    monkeypatch,
    confirm_paths,
    max_paths,
    confirmed_targets,
):
    if not confirm_paths:

        def unexpected_forward_paths(_tracer):
            pytest.fail("disabled confirmation must not enumerate forward paths")

        monkeypatch.setattr(
            SourceRootedPathTracer, "find_all_paths", unexpected_forward_paths
        )
    events = []
    options = ReachabilityReviewOptions(
        confirm_paths=confirm_paths,
        max_paths=max_paths,
        max_workers=1,
        lens_profile="review",
        source_functions=[{"name": "root", "reason": "configured entrypoint"}],
        security_functions=[{"name": "custom_copy", "sink_type": "buffer_overflow"}],
        progress_callback=events.append,
    )

    [review] = offline_reachability_service.review_codebase(
        options=options, files=["main.c", "notes.py"]
    )

    assert review["file"] == "main.c"
    [lens] = [item for item in review["reviews"] if item["analysis_type"] == "semantic"]
    assert lens["issue"] == "graph lens issue"
    assert lens["primary_function"] == "main.c::first"
    assert lens["line_number"] == 1
    assert lens["path"] == ["main.c::root", "main.c::first"]
    confirmed = [
        item for item in review["reviews"] if item["analysis_type"] == "reachability"
    ]
    assert [item["path"] for item in confirmed] == [
        ["main.c::root", target] for target in confirmed_targets
    ]
    assert len(review["reviews"]) == 1 + len(confirmed_targets)
    paths_done = [
        event for event in events if event["event"] == "treesitter_paths_done"
    ]
    assert paths_done == [
        {
            "event": "treesitter_paths_done",
            "paths": 2 if confirm_paths else 0,
            "selected": len(confirmed_targets),
            "confirmation_enabled": confirm_paths,
        }
    ]
    [done] = [
        event for event in events if event["event"] == "treesitter_code_review_done"
    ]
    assert done["supplementary_findings"] == 1
    assert done["path_findings"] == len(confirmed_targets)
    assert done["deduped_findings"] == 1 + len(confirmed_targets)
    graph = offline_reachability_service._graphs.ensure_graph(options=options)
    assert set(graph.nodes) == {"main.c::root", "main.c::first", "main.c::second"}
    assert [node.unique_name for node in graph.get_sources()] == ["main.c::root"]
    assert [(node.unique_name, node.sink_type) for node in graph.get_sinks()] == [
        ("main.c::first", "buffer_overflow")
    ]


@pytest.mark.parametrize("confirm_paths", [False, True])
def test_review_codebase_preserves_empty_graph_result(
    offline_reachability_service, confirm_paths
):
    assert (
        offline_reachability_service.review_codebase(
            options=ReachabilityReviewOptions(
                confirm_paths=confirm_paths, max_workers=1
            ),
            files=["notes.py"],
        )
        == []
    )


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
