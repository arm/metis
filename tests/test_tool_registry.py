# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.tools import (
    build_toolbox,
    get_builtin_tool_manifests,
    get_tool_contract,
    get_tool_config,
    get_tool_definitions,
    get_tool_manifest,
    registry,
)
from metis.engine.tools.catalog import _read_contract_ref
from metis.engine.tools.base import ToolContext, ToolDefinition


def test_tool_definitions_expose_named_tools():
    defs = get_tool_definitions()
    names = {tool.name for tool in defs}

    assert names == {"grep", "find_name", "cat", "sed"}
    assert all(tool.domains == ("triage_evidence",) for tool in defs)


def test_builtin_tool_catalog_exposes_active_and_planned_tools():
    statuses = {
        manifest.name: manifest.status for manifest in get_builtin_tool_manifests()
    }

    assert statuses["index"] == "active"
    assert statuses["navigation"] == "active"
    assert statuses["tree_sitter"] == "planned"
    assert statuses["mcp"] == "planned"


def test_navigation_tool_definitions_are_manifest_backed():
    manifest = get_tool_manifest("navigation")
    assert manifest is not None
    assert manifest.default_enabled is True
    manifest_tools = {
        capability.name
        for capability in manifest.capabilities
        if capability.status == "active"
    }
    definition_tools = {definition.name for definition in get_tool_definitions()}

    assert definition_tools == manifest_tools


def test_index_model_contract_loads_from_manifest():
    contract = get_tool_contract("index")

    assert "Index Tool Contract" in contract
    assert "index_search" in contract
    assert "Model usage rules" in contract


def test_index_tool_config_loads_manifest_defaults():
    config = get_tool_config("index")

    assert config["model_tool"]["max_rounds"] == 4
    assert config["search"]["max_top_k"] == 20
    assert config["search"]["default_max_chars"] == 12000
    assert config["search"]["max_chars"] == 24000


def test_tool_config_returns_isolated_copy():
    config = get_tool_config("index")
    config["search"]["max_top_k"] = 1

    assert get_tool_config("index")["search"]["max_top_k"] == 20


def test_local_contract_refs_are_not_cached(tmp_path):
    contract = tmp_path / "contract.md"
    contract.write_text("first", encoding="utf-8")

    assert _read_contract_ref(str(contract)) == "first"

    contract.write_text("second", encoding="utf-8")

    assert _read_contract_ref(str(contract)) == "second"


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
    assert toolbox.describe("grep") == {"backend": "shell_grep"}


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
