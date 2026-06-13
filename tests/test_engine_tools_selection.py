# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.engine.tools.selection import (
    DEFAULT_ENGINE_TOOLS,
    KNOWN_ENGINE_TOOLS,
    parse_engine_tools,
)


def test_parse_engine_tools_defaults_to_navigation():
    assert parse_engine_tools(None) == set(DEFAULT_ENGINE_TOOLS)
    assert parse_engine_tools("") == set(DEFAULT_ENGINE_TOOLS)
    assert DEFAULT_ENGINE_TOOLS == ("navigation",)


def test_parse_engine_tools_accepts_comma_separated_values():
    assert parse_engine_tools(" index ") == {"index"}
    assert parse_engine_tools(["index"]) == {"index"}
    assert parse_engine_tools("index,navigation") == {"index", "navigation"}


def test_parse_engine_tools_accepts_none_and_all_aliases():
    assert parse_engine_tools("none") == set()
    assert parse_engine_tools("all") == set(KNOWN_ENGINE_TOOLS)
    assert set(KNOWN_ENGINE_TOOLS) == {"index", "navigation"}


def test_parse_engine_tools_rejects_unknown_tools():
    with pytest.raises(ValueError, match="Unknown tool"):
        parse_engine_tools("index,unknown")


@pytest.mark.parametrize("tool_name", ["tree_sitter", "mcp"])
def test_parse_engine_tools_rejects_planned_tools_until_active(tool_name):
    with pytest.raises(ValueError, match="Unknown tool"):
        parse_engine_tools(tool_name)


def test_parse_engine_tools_rejects_mixed_none():
    with pytest.raises(ValueError, match="cannot be combined"):
        parse_engine_tools("none,index")
