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


def test_triage_collect_evidence_includes_analyzer_sections():
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

    out = triage_node_collect_evidence(state, tool_runner=runner)

    evidence_pack = out.get("evidence_pack", "")
    assert "[ANALYZER_SUMMARY]" in evidence_pack
    assert "[ANALYZER_CITATIONS]" in evidence_pack
    assert "src/main.c:12" in evidence_pack
    assert "[ANALYZER_RESOLUTION_CHAIN]" in evidence_pack
    assert "[ANALYZER_FLOW_CHAIN]" in evidence_pack
    assert "[FILE_WINDOW src/main.c" in evidence_pack
    assert runner.sed_calls > 0


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


def test_triage_collect_evidence_runs_fallback_when_analyzer_not_strong():
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

    out = triage_node_collect_evidence(state, tool_runner=runner)
    evidence_pack = out.get("evidence_pack", "")
    assert "[ANALYZER_FALLBACK]" in evidence_pack
    assert "[ANALYZER_UNRESOLVED]" in evidence_pack
    assert runner.grep_calls > 0


class _SupportedButUnresolvedAnalyzer:
    def collect_evidence(self, _request):
        return AnalyzerEvidence(
            supported=True,
            language="cpp",
            summary="tree-sitter found partial structural chain",
            citations=["src/main.cpp:50"],
            resolution_chain=["connect call observed at src/main.cpp:50"],
            unresolved_hops=["wrapper hop unresolved"],
            fallback_targets=["connectSocket"],
            sections=[],
        )


def test_triage_collect_evidence_runs_targeted_fallback_for_unresolved_hops():
    runner = _ToolRunner()
    state = {
        "finding_message": "connect wrapper issue",
        "finding_file_path": "src/main.cpp",
        "finding_line": 50,
        "finding_rule_id": "R2",
        "finding_snippet": "connect(fd, ...);",
        "triage_analyzer": _SupportedButUnresolvedAnalyzer(),
        "triage_codebase_path": ".",
    }

    out = triage_node_collect_evidence(state, tool_runner=runner)
    evidence_pack = out.get("evidence_pack", "")
    assert "[ANALYZER_SUMMARY]" in evidence_pack
    assert "[ANALYZER_UNRESOLVED]" in evidence_pack
    assert "[ANALYZER_FALLBACK_TARGETS]" in evidence_pack
    assert "TARGETED_GREP connectSocket" in evidence_pack
    assert runner.grep_calls > 0


class _RootOnlyHitRunner(_ToolRunner):
    def grep(self, pattern, path):
        self.grep_calls += 1
        if path == "." and "connectSocket" in pattern:
            return "benchmark/imatmul/imatmul_registry.cpp:52:    .run_imatmul = kai_run_connectSocket\n"
        return ""


class _CrossBoundaryAnalyzer:
    def collect_evidence(self, _request):
        return AnalyzerEvidence(
            supported=True,
            language="cpp",
            summary="tree-sitter found partial chain",
            citations=["src/main.cpp:50"],
            resolution_chain=["wrapper call observed at src/main.cpp:50"],
            unresolved_hops=["FLOW_EXTERNAL_CALLEE_UNRESOLVED:connectSocket"],
            fallback_targets=["connectSocket"],
            sections=[],
        )


def test_triage_collect_evidence_expands_targeted_recovery_to_repo_root():
    runner = _RootOnlyHitRunner()
    state = {
        "finding_message": "runtime dispatch unresolved",
        "finding_file_path": "src/main.cpp",
        "finding_line": 50,
        "finding_rule_id": "R3",
        "finding_snippet": "connectSocket(fd, ...);",
        "triage_analyzer": _CrossBoundaryAnalyzer(),
        "triage_codebase_path": ".",
    }

    out = triage_node_collect_evidence(state, tool_runner=runner)
    evidence_pack = out.get("evidence_pack", "")
    assert "TARGETED_GREP connectSocket IN ." in evidence_pack


def test_triage_collect_evidence_repo_root_search_not_skipped_for_nested_paths():
    runner = _RootOnlyHitRunner()
    state = {
        "finding_message": "cross-module chain unresolved",
        "finding_file_path": "src/nested/main.cpp",
        "finding_line": 50,
        "finding_rule_id": "R4",
        "finding_snippet": "connectSocket(fd, ...);",
        "triage_analyzer": _CrossBoundaryAnalyzer(),
        "triage_codebase_path": ".",
    }

    out = triage_node_collect_evidence(state, tool_runner=runner)
    evidence_pack = out.get("evidence_pack", "")
    assert "TARGETED_GREP connectSocket IN ." in evidence_pack
