# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import CancelledError
from unittest.mock import Mock

import pytest

from metis.engine.nodes.triage.workflow import triage_node_collect_evidence
from metis.engine.nodes.triage.workflow import constants as C


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
    observations = out["source_observations"]
    assert {observation["tool"] for observation in observations} == {"sed", "grep"}
    assert all(observation["output"] in evidence_pack for observation in observations)
    assert "source_observations" not in state


def test_triage_collect_evidence_retries_use_sites_with_grep():
    runner = _UseSiteRunner()
    state = {
        "finding_message": "Possible issue around helper",
        "finding_file_path": "src/main.py",
        "finding_line": 1,
        "finding_rule_id": "R1",
        "finding_snippet": "helper(user)",
        "codegraph_context": "x" * 20_000,
    }

    out = triage_node_collect_evidence(state, toolbox=runner)

    evidence_pack = out.get("evidence_pack", "")
    assert "[CALLER_GREP helper IN src]" in evidence_pack
    assert "[CALLER_CONTEXT src/caller.py:" in evidence_pack
    assert "TREE_SITTER" not in evidence_pack
    assert "ANALYZER_" not in evidence_pack
    assert any(
        observation["tool"] == "grep"
        and observation["arguments"]["path"] == "src"
        and observation["output"] == "src/caller.py:7:helper(42)\n"
        for observation in out["source_observations"]
    )


def test_triage_collect_evidence_probes_short_source_identifiers():
    runner = Mock()
    runner.sed.return_value = "1: a(user)"
    runner.grep.side_effect = lambda pattern, path: (
        "src/caller.py:7:a(42)\n" if path == "src" else ""
    )
    state = {
        "finding_file_path": "src/main.py",
        "finding_line": 1,
        "finding_message": "Possible issue around unrelated prose",
    }

    out = triage_node_collect_evidence(state, toolbox=runner)

    assert "[CALLER_GREP a IN src]" in out["evidence_pack"]
    assert "[CALLER_CONTEXT src/caller.py:" in out["evidence_pack"]


def test_triage_collect_evidence_propagates_cancellation():
    runner = Mock()
    runner.sed.side_effect = CancelledError

    with pytest.raises(CancelledError):
        triage_node_collect_evidence(
            {"finding_file_path": "src/main.py", "finding_line": 1},
            toolbox=runner,
        )


def test_triage_collect_evidence_excludes_removed_sections_and_stale_observations(
    monkeypatch,
):
    monkeypatch.setattr(C, "MAX_SECTIONS", 1)
    runner = Mock()
    runner.sed.return_value = "1: 0"
    runner.grep.return_value = ""
    state = {
        "finding_file_path": "src/main.py",
        "finding_line": 1,
        "source_observations": [{"output": "stale source"}],
    }

    out = triage_node_collect_evidence(state, toolbox=runner)

    assert "[REPORTED_LINE" not in out["evidence_pack"]
    assert out["source_observations"] == [
        {
            "tool": "sed",
            "arguments": {"path": "src/main.py", "start_line": 1, "end_line": 7},
            "output": "1: 0",
        }
    ]
    assert state["source_observations"] == [{"output": "stale source"}]


def test_triage_collect_evidence_tracks_only_visible_characters(monkeypatch):
    shown_source = "1: 12345\n2: 67"
    header = "[FILE_WINDOW src/main.py:1-7]\n"
    monkeypatch.setattr(C, "EVIDENCE_PACK_MAX_CHARS", len(header + shown_source))
    runner = Mock()
    runner.sed.return_value = "1: 12345\n2: 67890"
    runner.grep.return_value = ""

    out = triage_node_collect_evidence(
        {"finding_file_path": "src/main.py", "finding_line": 1},
        toolbox=runner,
    )

    assert out["evidence_pack"] == header + shown_source + "\n...[truncated]"
    assert out["source_observations"] == [
        {
            "tool": "sed",
            "arguments": {"path": "src/main.py", "start_line": 1, "end_line": 7},
            "output": shown_source,
        }
    ]
