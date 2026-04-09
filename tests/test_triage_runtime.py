# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine import triage_service_runtime


def test_triage_runtime_builds_graph_with_domain_toolbox(engine, monkeypatch):
    sentinel = object()
    captured = {}

    def _fake_build_toolbox(**kwargs):
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(triage_service_runtime, "build_toolbox", _fake_build_toolbox)

    graph = engine._triage_service._build_triage_graph()

    assert graph.toolbox is sentinel
    assert captured == {
        "policy": "triage_evidence",
        "codebase_path": engine.codebase_path,
        "timeout_seconds": engine.triage_tool_timeout_seconds,
    }
