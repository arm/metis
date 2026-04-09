# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.tools import build_toolbox, get_tool_definitions, registry
from metis.engine.tools.base import ToolContext, ToolDefinition


def test_tool_definitions_expose_named_tools():
    defs = get_tool_definitions()
    names = {tool.name for tool in defs}

    assert names == {"grep", "find_name", "cat", "sed"}
    assert all(tool.domains == ("triage_evidence",) for tool in defs)


def test_build_toolbox_for_policy_exposes_list_and_invocation(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("alpha\nbeta\n", encoding="utf-8")

    toolbox = build_toolbox(
        policy="triage_evidence", codebase_path=str(tmp_path), max_chars=200
    )

    assert toolbox.list_tools() == ("cat", "find_name", "grep", "sed")
    assert toolbox.has("grep") is True
    assert any(
        line.endswith("src/a.c:2:beta")
        for line in toolbox.grep("beta", "src").splitlines()
    )


def test_build_toolbox_rejects_unknown_policy(tmp_path):
    with pytest.raises(ValueError, match="Unknown tool policy"):
        build_toolbox(policy="bogus", codebase_path=str(tmp_path))


def test_validate_registry_rejects_duplicate_names(tmp_path):
    context = ToolContext(codebase_path=str(tmp_path))
    providers = registry._build_providers(context)
    defs = (
        ToolDefinition("grep", ("triage",), "static", "grep"),
        ToolDefinition("grep", ("triage",), "static", "sed"),
    )

    with pytest.raises(ValueError, match="Duplicate tool name"):
        registry._validate_registry(defs, providers)


def test_validate_registry_rejects_unknown_provider(tmp_path):
    defs = (ToolDefinition("grep", ("triage",), "missing", "grep"),)

    with pytest.raises(ValueError, match="Unknown tool provider"):
        registry._validate_registry(defs, providers={})


def test_validate_registry_rejects_missing_operation(tmp_path):
    context = ToolContext(codebase_path=str(tmp_path))
    providers = registry._build_providers(context)
    defs = (ToolDefinition("grep", ("triage",), "static", "missing_method"),)

    with pytest.raises(ValueError, match="missing operation"):
        registry._validate_registry(defs, providers)


def test_validate_policy_map_rejects_unknown_tool_name():
    defs = get_tool_definitions()
    with pytest.raises(ValueError, match="references unknown tool"):
        registry._validate_policy_map(defs, {"triage_evidence": ("missing_tool",)})


def test_validate_policy_map_rejects_duplicate_tool_name():
    defs = get_tool_definitions()
    with pytest.raises(ValueError, match="contains duplicate tool"):
        registry._validate_policy_map(defs, {"triage_evidence": ("grep", "grep")})
