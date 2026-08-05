# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


def test_triage_runtime_uses_the_granted_navigation_capability(engine):
    navigation = engine.capabilities["navigation"]

    workflow = engine._simple_llm_triage._workflow(navigation, 6)

    assert workflow.toolbox is navigation
    assert workflow.model_tool_max_rounds == 6


def test_triage_plugin_lookup_uses_manifest_filename_patterns(engine):
    plugin = engine._simple_llm_triage._get_plugin_for_path("rtl/cache_ctrl.sv.pp")

    assert plugin is not None
    assert plugin.get_name() == "systemverilog"
