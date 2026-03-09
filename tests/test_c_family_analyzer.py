# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.analysis.base import AnalyzerRequest
from metis.engine.analysis.c_family_analyzer import CFamilyTriageAnalyzer

C_EXTENSIONS = [".c", ".h", ".cc"]


class _Node:
    def __init__(self, node_type, *, text="", line=1, children=None, fields=None):
        self.type = node_type
        self.text = text
        self.start_point = (line - 1, 0)
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
    def __init__(self, root):
        self._root = root
        self.is_available = True
        self.init_error = ""

    def parse_file(self, _codebase_path, _rel_path):
        return _Parsed(self._root)


def test_c_family_analyzer_collects_definition_and_call(monkeypatch):
    from metis.engine.analysis import c_family_analyzer_common as mod

    monkeypatch.setattr(mod, "_node_text", lambda node, _source: node.text)

    decl_ident = _Node("identifier", text="foo", line=10)
    func_def = _Node(
        "function_definition",
        line=10,
        fields={
            "declarator": _Node("function_declarator", line=10, children=[decl_ident])
        },
    )

    call_ident = _Node("identifier", text="foo", line=20)
    call_expr = _Node(
        "call_expression",
        line=20,
        fields={"function": call_ident},
    )

    root = _Node("translation_unit", children=[func_def, call_expr, call_ident])

    analyzer = CFamilyTriageAnalyzer(
        codebase_path=".",
        language_name="c",
        supported_extensions=C_EXTENSIONS,
    )
    analyzer.runtime = _Runtime(root)

    out = analyzer.collect_evidence(
        AnalyzerRequest(
            codebase_path=".",
            file_path="src/main.c",
            line=20,
            finding_message="foo may be unsafe",
            finding_snippet="foo(x);",
            finding_rule_id="R1",
            candidate_symbols=["foo"],
            max_citations=8,
        )
    )

    assert out.supported is True
    assert "src/main.c:10" in out.citations
    assert "src/main.c:20" in out.citations
    assert out.resolution_chain
    assert out.flow_chain
    assert any(step.startswith("source at ") for step in out.flow_chain)
    assert any(
        "sink at " in step or "unknown at " in step for step in out.flow_chain
    ) or any(hop.startswith("FLOW_SINK_NOT_FOUND") for hop in out.unresolved_hops)


def test_c_family_analyzer_reports_unavailable_runtime():
    analyzer = CFamilyTriageAnalyzer(
        codebase_path=".",
        language_name="c",
        supported_extensions=C_EXTENSIONS,
    )
    analyzer.runtime._parser = None
    analyzer.runtime._init_error = "missing parser"

    out = analyzer.collect_evidence(
        AnalyzerRequest(
            codebase_path=".",
            file_path="src/main.c",
            line=1,
            finding_message="msg",
            finding_snippet="",
            finding_rule_id="R1",
        )
    )

    assert out.supported is False
    assert out.unresolved_hops


def test_c_family_analyzer_follows_interprocedural_path(monkeypatch):
    from metis.engine.analysis import c_family_analyzer_common as mod

    monkeypatch.setattr(mod, "_node_text", lambda node, _source: node.text)

    foo_decl = _Node("identifier", text="foo", line=10)
    foo_call_ident = _Node("identifier", text="bar", line=12)
    foo_call = _Node("call_expression", line=12, fields={"function": foo_call_ident})
    foo_def = _Node(
        "function_definition",
        text="int foo()",
        line=10,
        children=[foo_call],
        fields={
            "declarator": _Node("function_declarator", line=10, children=[foo_decl])
        },
    )

    bar_decl = _Node("identifier", text="bar", line=30)
    bar_call_ident = _Node("identifier", text="memcpy", line=35)
    bar_call = _Node("call_expression", line=35, fields={"function": bar_call_ident})
    bar_def = _Node(
        "function_definition",
        text="int bar()",
        line=30,
        children=[bar_call],
        fields={
            "declarator": _Node("function_declarator", line=30, children=[bar_decl])
        },
    )

    root = _Node("translation_unit", children=[foo_def, bar_def])

    analyzer = CFamilyTriageAnalyzer(
        codebase_path=".",
        language_name="c",
        supported_extensions=C_EXTENSIONS,
    )
    analyzer.runtime = _Runtime(root)

    out = analyzer.collect_evidence(
        AnalyzerRequest(
            codebase_path=".",
            file_path="src/main.c",
            line=11,
            finding_message="possible overflow through helper chain",
            finding_snippet="foo();",
            finding_rule_id="R2",
            candidate_symbols=["foo"],
            max_citations=12,
        )
    )

    assert out.supported is True
    assert out.flow_chain
    assert any("calls 'bar'" in step for step in out.flow_chain)
    assert any("calls 'memcpy'" in step for step in out.flow_chain)


def test_c_family_analyzer_resolves_unresolved_hop_across_codebase(tmp_path):
    src = tmp_path / "proj"
    src.mkdir()
    file_path = src / "main.c"
    file_path.write_text("int helper(int x) { return x + 1; }\n", encoding="utf-8")

    analyzer = CFamilyTriageAnalyzer(
        codebase_path=str(src),
        language_name="c",
        supported_extensions=C_EXTENSIONS,
    )
    remaining, sections, citations, resolution = (
        analyzer._resolve_unresolved_hops_across_codebase(
            unresolved_hops=["FLOW_EXTERNAL_CALLEE_UNRESOLVED:helper"],
            codebase_path=str(src),
            file_path="main.c",
            top_symbol_hint=["helper"],
        )
    )

    assert remaining == []
    assert sections
    assert citations
    assert resolution


def test_c_family_analyzer_fallback_targets_filter_macro_noise():
    analyzer = CFamilyTriageAnalyzer(
        codebase_path=".",
        language_name="c",
        supported_extensions=C_EXTENSIONS,
    )
    targets = analyzer._compute_fallback_targets_from_unresolved(
        unresolved_hops=[
            "FLOW_EXTERNAL_CALLEE_UNRESOLVED:__ARM_FEATURE_SVE2",
            "FLOW_EXTERNAL_CALLEE_UNRESOLVED:helper",
            "MACRO_SEMANTICS_UNRESOLVED:PROJECT_ASSUME",
        ],
        preferred_symbols=["__aarch64__", "helper", "PROJECT_ASSUME"],
        limit=8,
    )

    assert "helper" in targets
    assert "__ARM_FEATURE_SVE2" not in targets
    assert "__aarch64__" not in targets


def test_c_family_analyzer_resolves_macro_chain(tmp_path):
    src = tmp_path / "proj"
    src.mkdir()
    hdr = src / "project_common.h"
    hdr.write_text(
        "#define PROJECT_ASSERT_MSG(cond,msg) do{}while(0)\n"
        "#define PROJECT_ASSERT(cond) PROJECT_ASSERT_MSG(cond,#cond)\n"
        "#define PROJECT_ASSUME PROJECT_ASSERT\n",
        encoding="utf-8",
    )
    cfile = src / "main.c"
    cfile.write_text('#include "project_common.h"\nint x;\n', encoding="utf-8")

    analyzer = CFamilyTriageAnalyzer(
        codebase_path=str(src),
        language_name="c",
        supported_extensions=C_EXTENSIONS,
    )
    sections, citations, resolution, unresolved = analyzer._analyze_macro_semantics(
        symbols=["PROJECT_ASSUME"],
        include_files=["main.c", "project_common.h"],
        codebase_path=str(src),
    )

    assert sections
    assert citations
    assert resolution
    assert not any("MACRO_SEMANTICS_UNRESOLVED:PROJECT_ASSUME" == u for u in unresolved)


def test_c_family_analyzer_prefers_asm_impl_when_decl_and_asm_exist():
    analyzer = CFamilyTriageAnalyzer(
        codebase_path=".",
        language_name="c",
        supported_extensions=C_EXTENSIONS,
    )

    class _Hit:
        def __init__(self, symbol, file_path, line, kind):
            self.symbol = symbol
            self.file_path = file_path
            self.line = line
            self.kind = kind

    hit = analyzer._choose_best_symbol_hit(
        [
            _Hit("project_commit", "src/project_common.h", 225, "declaration"),
            _Hit("project_commit", "src/project_impl.S", 48, "asm_label"),
        ]
    )
    assert "asm_impl" in hit.kind
