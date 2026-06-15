# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.graphs.triage import triage_node_collect_evidence


class _NavigationEvidenceRunner:
    def __init__(self):
        self.grep_calls = 0
        self.sed_calls = 0

    def sed(self, path, start, end):
        self.sed_calls += 1
        if path == "src/main.py":
            return "def helper(value):\n    return value\nvalue = helper(user)\n"
        return ""

    def grep(self, pattern, path):
        self.grep_calls += 1
        if path == "src/main.py" and "helper" in pattern:
            return "src/main.py:1:def helper(value):\n"
        return ""

    def find_name(self, _name, max_results=20):
        return []

    def describe(self, name):
        return {"backend": f"test_{name}"}


class _UseSiteRunner(_NavigationEvidenceRunner):
    def sed(self, path, start, end):
        self.sed_calls += 1
        if path == "src/main.py":
            return "value = helper(user)\n"
        if path == "src/caller.py":
            return "def caller():\n    helper(42)\n"
        return ""

    def grep(self, pattern, path):
        self.grep_calls += 1
        if path == "src" and "helper" in pattern:
            return "src/caller.py:7:helper(42)\n"
        return ""


def test_triage_collect_evidence_uses_navigation_without_analyzer_sections():
    runner = _NavigationEvidenceRunner()
    state = {
        "finding_message": "Possible issue around helper",
        "finding_file_path": "src/main.py",
        "finding_line": 3,
        "finding_rule_id": "R1",
        "finding_snippet": "helper(user)",
    }

    out = triage_node_collect_evidence(state, toolbox=runner)

    evidence_pack = out.get("evidence_pack", "")
    assert "[FILE_WINDOW src/main.py" in evidence_pack
    assert "[REPORTED_LINE src/main.py:3]" in evidence_pack
    assert "[SYMBOL_GREP helper IN src/main.py (local)]" in evidence_pack
    assert "[HIT_CONTEXT src/main.py:" in evidence_pack
    assert "TREE_SITTER" not in evidence_pack
    assert "ANALYZER_" not in evidence_pack
    assert runner.sed_calls > 0
    assert runner.grep_calls > 0


def test_triage_collect_evidence_retries_use_sites_with_grep():
    runner = _UseSiteRunner()
    state = {
        "finding_message": "Possible issue around helper",
        "finding_file_path": "src/main.py",
        "finding_line": 1,
        "finding_rule_id": "R1",
        "finding_snippet": "helper(user)",
    }

    out = triage_node_collect_evidence(state, toolbox=runner)

    evidence_pack = out.get("evidence_pack", "")
    assert "[CALLER_GREP helper IN src]" in evidence_pack
    assert "[CALLER_CONTEXT src/caller.py:" in evidence_pack
    assert "TREE_SITTER" not in evidence_pack
    assert "ANALYZER_" not in evidence_pack
