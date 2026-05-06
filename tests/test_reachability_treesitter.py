# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.reachability_service import PathTracer
from metis.engine.reachability_service_modular.builder import (
    TreeSitterReachabilityGraphBuilder,
)


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
