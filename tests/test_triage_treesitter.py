# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.analysis.base import AnalyzerEvidence
from metis.engine.graphs.triage import triage_node_collect_evidence


class _Analyzer:
    def collect_evidence(self, _request):
        return AnalyzerEvidence(
            supported=True,
            language="c",
            summary="Tree-sitter(c) analyzed src/main.c",
            citations=["src/main.c:12", "src/main.c:31"],
            resolution_chain=["foo definition resolved", "foo call observed"],
            flow_chain=[
                "source at src/main.c:20 - reported context",
                "sink at src/main.c:31 - call 'foo'",
            ],
            unresolved_hops=[],
            sections=["foo: defs=12 | calls=31"],
        )


class _WeakAnalyzer:
    def collect_evidence(self, _request):
        return AnalyzerEvidence(
            supported=False,
            language="c",
            summary="partial analyzer result",
            citations=["src/main.c:12"],
            resolution_chain=[],
            unresolved_hops=["wrapper unresolved"],
            sections=[],
        )


class _ToolRunner:
    def __init__(self):
        self.sed_calls = 0
        self.cat_calls = 0
        self.grep_calls = 0

    def sed(self, _path, _start, _end):
        self.sed_calls += 1
        return ""

    def cat(self, _path):
        self.cat_calls += 1
        return ""

    def grep(self, _pattern, _path):
        self.grep_calls += 1
        return ""

    def find_name(self, _name, max_results=20):
        return []

    def describe(self, name):
        return {"backend": f"test_{name}"}


class _CaptureToolRunner(_ToolRunner):
    def __init__(self):
        super().__init__()
        self.grep_paths = []
        self.grep_patterns = []

    def grep(self, pattern, path):
        self.grep_calls += 1
        self.grep_paths.append(path)
        self.grep_patterns.append(pattern)
        return ""


class _MacroExpandRunner(_ToolRunner):
    def grep(self, pattern, path):
        self.grep_calls += 1
        if path.endswith("src/main.c") and "include" in pattern:
            return 'src/main.c:1:#include "project_support.h"\\n'
        if (
            "define" in pattern
            and "PROJECT_STACK_ALLOC" in pattern
            and "project_support.h" in path
        ):
            return "project_support.h:35:#define PROJECT_STACK_ALLOC alloca\\n"
        if (
            "PROJECT_STACK_ALLOC" in pattern
            and "define" not in pattern
            and path.endswith("src/main.c")
        ):
            return "src/main.c:20:data = (int*)PROJECT_STACK_ALLOC(10);\\n"
        return ""

    def sed(self, path, start, end):
        self.sed_calls += 1
        if "project_support.h" in path:
            return "#define PROJECT_STACK_ALLOC alloca\\n"
        return ""


class _MacroFindNameRunner(_ToolRunner):
    def grep(self, pattern, path):
        self.grep_calls += 1
        if path.endswith("src/main.c") and "include" in pattern:
            return 'src/main.c:1:#include "project_support.h"\\n'
        if (
            "define" in pattern
            and "PROJECT_STACK_ALLOC" in pattern
            and "include/project_support.h" in path
        ):
            return "include/project_support.h:35:#define PROJECT_STACK_ALLOC alloca\\n"
        return ""

    def sed(self, path, start, end):
        self.sed_calls += 1
        if "include/project_support.h" in path:
            return "#define PROJECT_STACK_ALLOC alloca\\n"
        return ""

    def find_name(self, name, max_results=20):
        if name == "project_support.h":
            return ["include/project_support.h"]
        return []


def test_triage_collect_evidence_includes_analyzer_sections_and_scope_section():
    runner = _ToolRunner()
    state = {
        "finding_message": "Possible issue around foo",
        "finding_file_path": "src/main.c",
        "finding_line": 20,
        "finding_rule_id": "R1",
        "finding_snippet": "foo(x);",
        "triage_analyzer": _Analyzer(),
        "triage_codebase_path": ".",
    }

    out = triage_node_collect_evidence(state, toolbox=runner)

    evidence_pack = out.get("evidence_pack", "")
    assert "[ANALYZER_SUMMARY]" in evidence_pack
    assert "[ANALYZER_CITATIONS]" in evidence_pack
    assert "src/main.c:12" in evidence_pack
    assert "[ANALYZER_RESOLUTION_CHAIN]" in evidence_pack
    assert "[ANALYZER_FLOW_CHAIN]" in evidence_pack
    assert "[FILE_WINDOW src/main.c" in evidence_pack
    assert "[TREE_SITTER_SCOPE]" in evidence_pack
    assert out.get("evidence_obligations")
    assert isinstance(out.get("obligation_coverage"), dict)
    assert runner.sed_calls > 0


def test_triage_collect_evidence_runs_definition_grep_when_analyzer_weak():
    runner = _ToolRunner()
    state = {
        "finding_message": "Possible issue around foo and bar",
        "finding_file_path": "src/main.c",
        "finding_line": 20,
        "finding_rule_id": "R1",
        "finding_snippet": "foo(x); bar(y);",
        "triage_analyzer": _WeakAnalyzer(),
        "triage_codebase_path": ".",
    }

    out = triage_node_collect_evidence(state, toolbox=runner)
    evidence_pack = out.get("evidence_pack", "")
    assert "[ANALYZER_FALLBACK]" in evidence_pack
    assert "[ANALYZER_UNRESOLVED]" in evidence_pack
    assert "SYMBOL_GREP" in evidence_pack
    assert runner.grep_calls > 0


def test_triage_collect_evidence_enforces_max_sections(monkeypatch):
    runner = _ToolRunner()
    monkeypatch.setattr("metis.engine.graphs.triage.constants.MAX_SECTIONS", 5)
    state = {
        "finding_message": "Possible issue around foo and bar",
        "finding_file_path": "src/main.c",
        "finding_line": 20,
        "finding_rule_id": "R1",
        "finding_snippet": "foo(x); bar(y);",
        "triage_analyzer": _WeakAnalyzer(),
        "triage_codebase_path": ".",
    }

    out = triage_node_collect_evidence(state, toolbox=runner)

    evidence_pack = out.get("evidence_pack", "")
    sections = [s for s in evidence_pack.split("\n\n") if s.strip()]
    assert len(sections) <= 5


def test_triage_collect_evidence_external_source_uses_line_local_profile():
    runner = _CaptureToolRunner()
    state = {
        "finding_message": "Possible issue around foo",
        "finding_file_path": "src/main.c",
        "finding_line": 20,
        "finding_rule_id": "R1",
        "finding_snippet": "foo(x);",
        "finding_is_metis": False,
        "triage_analyzer": _Analyzer(),
        "triage_codebase_path": ".",
    }

    out = triage_node_collect_evidence(state, toolbox=runner)
    evidence_pack = out.get("evidence_pack", "")
    assert "[FILE_HEAD src/main.c]" not in evidence_pack
    assert all(path == "src/main.c" for path in runner.grep_paths)


def test_triage_collect_evidence_metis_appends_explanation_section():
    runner = _CaptureToolRunner()
    state = {
        "finding_message": "Possible issue around foo",
        "finding_file_path": "src/main.c",
        "finding_line": 20,
        "finding_rule_id": "R1",
        "finding_snippet": "foo(x);",
        "finding_is_metis": True,
        "finding_explanation": "reasoning: foo reaches sink",
        "triage_analyzer": _Analyzer(),
        "triage_codebase_path": ".",
    }

    out = triage_node_collect_evidence(state, toolbox=runner)
    evidence_pack = out.get("evidence_pack", "")
    assert "[METIS_EXPLANATION]" in evidence_pack
    assert "reasoning: foo reaches sink" in evidence_pack


def test_triage_collect_evidence_uses_portable_grep_patterns():
    runner = _CaptureToolRunner()
    state = {
        "finding_message": "Possible issue around foo",
        "finding_file_path": "src/main.c",
        "finding_line": 20,
        "finding_rule_id": "R1",
        "finding_snippet": "foo(x);",
        "triage_analyzer": _WeakAnalyzer(),
        "triage_codebase_path": ".",
    }

    triage_node_collect_evidence(state, toolbox=runner)

    assert any("[[:space:]]*\\(" in pattern for pattern in runner.grep_patterns)
    assert any("[[:space:]]*=" in pattern for pattern in runner.grep_patterns)
    assert all("\\s*" not in pattern for pattern in runner.grep_patterns)


def test_triage_collect_evidence_resolves_macro_definition_with_tools():
    runner = _MacroExpandRunner()
    state = {
        "finding_message": "alloca called",
        "finding_file_path": "src/main.c",
        "finding_line": 20,
        "finding_rule_id": "R1",
        "finding_snippet": "data = (int*)PROJECT_STACK_ALLOC(10);",
        "triage_analyzer": _Analyzer(),
        "triage_codebase_path": ".",
    }

    out = triage_node_collect_evidence(state, toolbox=runner)
    evidence_pack = out.get("evidence_pack", "")
    assert "MACRO_DEFINE_GREP PROJECT_STACK_ALLOC IN project_support.h" in evidence_pack
    assert "MACRO_DEFINE_CONTEXT PROJECT_STACK_ALLOC project_support.h" in evidence_pack
    assert "[MACRO_RESOLUTION]\nPROJECT_STACK_ALLOC -> alloca" in evidence_pack


def test_triage_collect_evidence_resolves_macro_definition_via_find_name():
    runner = _MacroFindNameRunner()
    state = {
        "finding_message": "alloca called",
        "finding_file_path": "src/main.c",
        "finding_line": 20,
        "finding_rule_id": "R1",
        "finding_snippet": "data = (int*)PROJECT_STACK_ALLOC(10);",
        "triage_analyzer": _Analyzer(),
        "triage_codebase_path": ".",
    }

    out = triage_node_collect_evidence(state, toolbox=runner)
    evidence_pack = out.get("evidence_pack", "")
    assert (
        "MACRO_DEFINE_GREP PROJECT_STACK_ALLOC IN include/project_support.h"
        in evidence_pack
    )
    assert "[MACRO_RESOLUTION]\nPROJECT_STACK_ALLOC -> alloca" in evidence_pack


def test_triage_collect_evidence_emits_evidence_gate_debug_event():
    runner = _ToolRunner()
    events = []
    state = {
        "finding_message": "Possible issue around foo and bar",
        "finding_file_path": "src/main.c",
        "finding_line": 20,
        "finding_rule_id": "R1",
        "finding_snippet": "foo(x); bar(y);",
        "triage_analyzer": _WeakAnalyzer(),
        "triage_codebase_path": ".",
        "debug_callback": events.append,
    }

    out = triage_node_collect_evidence(state, toolbox=runner)

    assert out["evidence_gate_missing"] == ["OBLIGATION_MISSING:use_site"]
    gate_events = [event for event in events if event.get("event") == "evidence_gate"]
    assert len(gate_events) == 1
    assert gate_events[0]["missing"] == ["OBLIGATION_MISSING:use_site"]
    assert "FILE_WINDOW src/main.c:14-26" in gate_events[0]["section_labels"]
    assert "SYMBOL_GREP foo IN src/main.c (local)" in gate_events[0]["section_labels"]


def test_triage_debug_tool_calls_include_backend():
    runner = _ToolRunner()
    events = []
    state = {
        "finding_message": "Possible issue around foo and bar",
        "finding_file_path": "src/main.c",
        "finding_line": 20,
        "finding_rule_id": "R1",
        "finding_snippet": "foo(x); bar(y);",
        "triage_analyzer": _WeakAnalyzer(),
        "triage_codebase_path": ".",
        "debug_callback": events.append,
    }

    triage_node_collect_evidence(state, toolbox=runner)

    grep_event = next(
        event
        for event in events
        if event.get("event") == "tool_call" and event.get("tool_name") == "grep"
    )
    assert grep_event["tool_args"]["backend"] == "test_grep"


def test_triage_collect_evidence_skips_duplicate_fallback_probe_for_local_file():
    runner = _ToolRunner()
    events = []
    state = {
        "finding_message": "Possible issue around foo",
        "finding_file_path": "src/main.c",
        "finding_line": 20,
        "finding_rule_id": "R1",
        "finding_snippet": "foo(x);",
        "triage_analyzer": _WeakAnalyzer(),
        "triage_codebase_path": ".",
        "debug_callback": events.append,
    }

    triage_node_collect_evidence(state, toolbox=runner)

    symbol_grep_events = [
        event
        for event in events
        if event.get("event") == "tool_call"
        and event.get("tool_name") == "grep"
        and event.get("tool_args", {}).get("path") == "src/main.c"
    ]
    assert symbol_grep_events
    assert all(
        event.get("tool_args", {}).get("mode") != "fallback"
        for event in symbol_grep_events
    )
