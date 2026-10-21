# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import CancelledError
from unittest.mock import Mock

import pytest

from metis.engine.nodes.triage.workflow import triage_node_collect_evidence
from metis.engine.nodes.triage.workflow import constants as C


@pytest.mark.parametrize("is_metis, radius", [(False, 6), (True, 8)])
def test_triage_collect_evidence_reads_one_window(is_metis, radius):
    runner = Mock()
    runner.sed.return_value = "10: helper(user)"
    events = []
    state = {
        "finding_file_path": "src/main.py",
        "finding_line": 10,
        "finding_is_metis": is_metis,
        "source_observations": [{"output": "stale source"}],
        "debug_callback": events.append,
    }

    out = triage_node_collect_evidence(state, toolbox=runner)

    runner.sed.assert_called_once_with("src/main.py", 10 - radius, 10 + radius)
    runner.grep.assert_not_called()
    arguments = {
        "path": "src/main.py",
        "start_line": 10 - radius,
        "end_line": 10 + radius,
    }
    assert out["source_observations"] == [
        {"tool": "sed", "arguments": arguments, "output": "10: helper(user)"}
    ]
    assert state["source_observations"] == [{"output": "stale source"}]
    assert out["evidence_pack"] == (
        f"[FILE_WINDOW src/main.py:{10 - radius}-{10 + radius}]\n10: helper(user)"
    )
    assert [event["event"] for event in events] == ["tool_call", "evidence_collection"]
    assert events[0]["tool_args"] == arguments
    events[0]["tool_args"]["path"] = "unobserved.py"
    assert out["source_observations"][0]["arguments"] == arguments


@pytest.mark.parametrize(
    "template", ["{triage_input}\n{tool_outputs}", "{tool_outputs}"]
)
def test_triage_collect_evidence_keeps_hints_separate_from_source(template):
    runner = Mock()
    runner.sed.return_value = "1: helper(user)"
    state = {
        "finding_file_path": "src/main.py",
        "finding_line": 1,
        "finding_is_metis": True,
        "finding_explanation": "2: explanation is not inspected source",
        "codegraph_context": "3: graph hint is not inspected source",
        "triage_decision_prompt": template,
    }

    out = triage_node_collect_evidence(state, toolbox=runner)

    assert ("[METIS_EXPLANATION]" in out["evidence_pack"]) == (
        "{triage_input}" not in template
    )
    assert "[CODEGRAPH_CONTEXT]\n3: graph hint" in out["evidence_pack"]
    assert len(out["source_observations"]) == 1
    assert out["source_observations"][0]["output"] == "1: helper(user)"


def test_triage_collect_evidence_propagates_cancellation():
    runner = Mock()
    runner.sed.side_effect = CancelledError

    with pytest.raises(CancelledError):
        triage_node_collect_evidence(
            {"finding_file_path": "src/main.py", "finding_line": 1},
            toolbox=runner,
        )


def test_triage_collect_evidence_reports_read_failure_without_source():
    runner = Mock()
    runner.sed.side_effect = OSError("1: error text is not source")
    events = []

    out = triage_node_collect_evidence(
        {"finding_file_path": "src/main.py", "debug_callback": events.append},
        toolbox=runner,
    )

    assert out["evidence_pack"] == "[FILE_WINDOW_ERROR]\n1: error text is not source"
    assert out["source_observations"] == []
    assert events[0]["tool_output"] == (
        "Tool execution failed: 1: error text is not source"
    )


@pytest.mark.parametrize(
    "limit", ["DEFAULT_CAPTURE_MAX_CHARS", "EVIDENCE_PACK_MAX_CHARS"]
)
def test_triage_collect_evidence_tracks_only_visible_characters(monkeypatch, limit):
    shown_source = "1: 12345\n2: 67"
    header = "[FILE_WINDOW src/main.py:1-7]\n"
    max_chars = len(shown_source)
    if limit == "EVIDENCE_PACK_MAX_CHARS":
        max_chars += len(header)
    monkeypatch.setattr(C, limit, max_chars)
    runner = Mock()
    runner.sed.return_value = "1: 12345\n2: 67890"

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
