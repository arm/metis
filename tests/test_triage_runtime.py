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


def test_triage_plugin_lookup_uses_manifest_filename_patterns(engine):
    plugin = engine._triage_service._get_triage_plugin("rtl/cache_ctrl.sv.pp")

    assert plugin is not None
    assert plugin.get_name() == "systemverilog"


def test_triage_analyzer_cache_uses_resolved_language_name(engine, monkeypatch):
    service = engine._triage_service
    analyzer = object()
    plugin_paths = []
    factory_paths = []

    class _Plugin:
        def get_triage_analyzer_factory(self):
            def _factory(codebase_path):
                factory_paths.append(codebase_path)
                return analyzer

            return _factory

    def _language_name_for_path(path):
        if ".demo." in path:
            return "demo"
        return None

    def _plugin_for_path(path):
        plugin_paths.append(path)
        return _Plugin()

    monkeypatch.setattr(service, "_get_language_name_for_path", _language_name_for_path)
    monkeypatch.setattr(service, "_get_plugin_for_path", _plugin_for_path)

    first = service._get_thread_triage_analyzer("rtl/a.demo.generated")
    second = service._get_thread_triage_analyzer("rtl/b.demo.preprocessed")

    assert first is analyzer
    assert second is analyzer
    assert plugin_paths == ["rtl/a.demo.generated"]
    assert factory_paths == [engine.codebase_path]
