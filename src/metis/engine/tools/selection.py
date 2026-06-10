# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Collection, Iterable


INDEX_TOOL = "index"
KNOWN_ENGINE_TOOLS = (INDEX_TOOL,)
DEFAULT_ENGINE_TOOLS: tuple[str, ...] = ()


def format_known_engine_tools() -> str:
    return ", ".join(sorted(KNOWN_ENGINE_TOOLS))


def parse_engine_tools(value: object | None) -> set[str]:
    if value is None:
        return set(DEFAULT_ENGINE_TOOLS)

    raw_items: list[str] = []
    explicit_iterable = False
    if isinstance(value, str):
        raw_items.extend(value.split(","))
    elif isinstance(value, Iterable):
        explicit_iterable = True
        for item in value:
            raw_items.extend(str(item).split(","))
    else:
        raw_items.extend(str(value).split(","))

    tools = [item.strip().lower() for item in raw_items if item.strip()]
    if not tools:
        return set() if explicit_iterable else set(DEFAULT_ENGINE_TOOLS)

    if "none" in tools:
        if len(tools) > 1:
            raise ValueError("--tools none cannot be combined with other tools")
        return set()

    if "all" in tools:
        if len(tools) > 1:
            raise ValueError("--tools all cannot be combined with other tools")
        return set(KNOWN_ENGINE_TOOLS)

    unknown = sorted(set(tools) - set(KNOWN_ENGINE_TOOLS))
    if unknown:
        known = format_known_engine_tools()
        raise ValueError(
            f"Unknown tool(s): {', '.join(unknown)}. Known tools: {known}, all, none"
        )
    return set(tools)


def tool_enabled(enabled_tools: Collection[str], name: str) -> bool:
    return name in enabled_tools
