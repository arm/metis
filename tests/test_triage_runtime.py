# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import CancelledError
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import FunctionNode
from metis.engine.stages.triage.service import TriageService


def test_triage_runtime_uses_the_granted_navigation_capability(engine):
    navigation = engine.capabilities["navigation"]

    workflow = engine._triage_classifier._workflow(navigation, 6)

    assert workflow.toolbox is navigation
    assert workflow.model_tool_max_rounds == 6
    assert workflow.max_input_tokens == engine._config.max_token_length


@pytest.mark.parametrize("error", [OSError("disk full"), ValueError("invalid JSON")])
def test_triage_checkpoint_logs_write_failures(monkeypatch, caplog, tmp_path, error):
    writer = Mock(side_effect=error)
    monkeypatch.setattr("metis.engine.stages.triage.service.save_sarif_file", writer)
    target = str(tmp_path / "checkpoint.sarif")
    checkpoint = TriageService(triage_checkpoint_every=1).checkpoint_callback(target)

    checkpoint({"version": "2.1.0", "runs": []}, 1, 1)

    assert "Unable to save triage checkpoint" in caplog.text
    assert target in caplog.text
    assert str(error) in caplog.text
    writer.side_effect = CancelledError("cancelled")
    with pytest.raises(CancelledError, match="cancelled"):
        checkpoint({"version": "2.1.0", "runs": []}, 1, 1)


def test_triage_plugin_lookup_uses_manifest_filename_patterns(engine):
    plugin = engine._triage_classifier._get_plugin_for_path("rtl/cache_ctrl.sv.pp")

    assert plugin is not None
    assert plugin.get_name() == "systemverilog"


def test_triage_adds_available_codegraph_evidence(engine, monkeypatch):
    graph = CodeGraph()
    graph.add_node(
        FunctionNode(
            "src/example.c::target",
            "src/example.c",
            "target",
            10,
            end_line=20,
            resolved_calls=["src/example.c::sink"],
        )
    )
    graph.add_node(
        FunctionNode(
            "src/example.c::sink",
            "src/example.c",
            "sink",
            30,
        )
    )
    workflow = Mock()
    monkeypatch.setattr(
        engine._triage_classifier,
        "_workflow",
        lambda _navigation, _rounds, _model=None: workflow,
    )

    engine._triage_classifier.classify(
        SimpleNamespace(
            message="issue",
            file_path="src/example.c",
            line=12,
            rule_id="R1",
            snippet="target();",
        ),
        [],
        None,
        navigation=engine.capabilities["navigation"],
        codegraph=graph,
    )

    request = workflow.triage.call_args.args[0]
    assert "target: src/example.c::target" in request["codegraph_context"]
    assert "direct callees: src/example.c::sink" in request["codegraph_context"]

    engine._triage_classifier.classify(
        SimpleNamespace(
            message="issue",
            file_path="src/example.c",
            line=12,
            rule_id="R1",
            snippet="target();",
        ),
        [],
        None,
        navigation=engine.capabilities["navigation"],
        codegraph=graph,
        unavailable_files=("src/example.c",),
    )

    request = workflow.triage.call_args.args[0]
    assert "codegraph_context" not in request
