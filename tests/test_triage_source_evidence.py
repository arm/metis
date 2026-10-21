# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.capabilities.navigation import NavigationCapability
from metis.engine.nodes.triage.workflow.source_evidence import SourceEvidence
from metis.engine.stages.triage.models import TriageDecisionModel


def _decision(citation, status="valid"):
    return TriageDecisionModel(
        status=status,
        reason="Source supports the decision.",
        evidence=[citation],
        resolution_chain=["reported operation -> inspected source"],
    )


@pytest.mark.parametrize("tool", ["sed", "cat", "grep"])
def test_source_evidence_checks_observed_lines_and_internal_symlinks(tmp_path, tool):
    source = tmp_path / "source file.py"
    source.write_text("before = 1\nvalue = input()\nafter = 2\n", encoding="utf-8")
    alias = tmp_path / "alias.py"
    alias.symlink_to(source)
    ledger = SourceEvidence(tmp_path, [])
    arguments = {"path": alias.name, "start_line": 2, "end_line": 2}
    output = "alias.py:2:value = input()" if tool == "grep" else " 2: value = input()"

    ledger.observe(tool, arguments, output)

    assert ledger.validate(_decision("source file.py:2")) == []
    assert ledger.validate(_decision("alias.py:3")) == [
        "UNOBSERVED_CITATION:alias.py:3"
    ]


def test_truncated_source_line_cannot_authorize_a_citation(tmp_path):
    (tmp_path / "a.py").write_text("value = input()\n", encoding="utf-8")
    ledger = SourceEvidence(tmp_path, [])
    ledger.observe("cat", {"path": "a.py"}, "1: value = inp\n...[truncated]")

    assert ledger.validate(_decision("a.py:1")) == ["SOURCE_CHANGED:a.py:1"]

    ledger.observe("cat", {"path": "a.py"}, "1: value = input()")
    ledger.observe("cat", {"path": "a.py"}, "1: value = inp\n...[truncated]")
    assert ledger.validate(_decision("a.py:1")) == []


@pytest.mark.parametrize("citation", ["a.py:one", "../outside.py:1"])
def test_source_evidence_rejects_invalid_citations(tmp_path, citation):
    assert SourceEvidence(tmp_path, []).validate(_decision(citation)) == [
        f"INVALID_CITATION:{citation}"
    ]


def test_source_evidence_bounds_ranges_to_observed_lines(tmp_path):
    (tmp_path / "a.py").write_text("one\ntwo\nthree\n", encoding="utf-8")
    ledger = SourceEvidence(tmp_path, [])
    ledger.observe("cat", {"path": "a.py"}, "1: one\n2: two")

    assert ledger.validate(_decision("a.py:1-2")) == []
    for citation in ("a.py:2-1", "a.py:1-3", "a.py:1-999999999999999999999"):
        assert ledger.validate(_decision(citation)) == [
            f"UNOBSERVED_CITATION:{citation}"
        ]


def test_source_evidence_rejects_source_changes_and_read_failures(tmp_path):
    source = tmp_path / "a.py"
    source.write_text("before\n", encoding="utf-8")
    ledger = SourceEvidence(tmp_path, [])
    ledger.observe("cat", {"path": "a.py"}, "1: before")
    source.write_text("after\n", encoding="utf-8")
    assert ledger.validate(_decision("a.py:1")) == ["SOURCE_CHANGED:a.py:1"]
    source.unlink()
    assert ledger.validate(_decision("a.py:1")) == ["SOURCE_UNAVAILABLE:a.py:1"]


def test_source_evidence_discards_tool_only_lines_before_prompt_only_fallback(tmp_path):
    (tmp_path / "a.py").write_text("initial\nextra\n", encoding="utf-8")
    ledger = SourceEvidence(
        tmp_path,
        [{"tool": "cat", "arguments": {"path": "a.py"}, "output": "1: initial"}],
    )
    ledger.observe("sed", {"path": "a.py", "start_line": 2, "end_line": 2}, "2: extra")
    assert ledger.validate(_decision("a.py:2")) == []

    ledger.reset_tools()

    assert ledger.validate(_decision("a.py:1")) == []
    assert ledger.validate(_decision("a.py:2")) == ["UNOBSERVED_CITATION:a.py:2"]


def test_source_evidence_accepts_native_grep_whitespace_normalization(tmp_path):
    (tmp_path / "a.py").write_text("safe = sanitize(value)   \n", encoding="utf-8")
    navigation = NavigationCapability(
        codebase_path=str(tmp_path), timeout_seconds=8, max_chars=16000
    )
    if not navigation._has_grep:
        pytest.skip("native grep unavailable")
    ledger = SourceEvidence(tmp_path, [])
    ledger.observe("grep", {"path": "a.py"}, navigation.grep("sanitize", "a.py"))

    assert ledger.validate(_decision("a.py:1", "invalid")) == []
