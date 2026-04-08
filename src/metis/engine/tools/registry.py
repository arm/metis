# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from .base import ToolBox, ToolContext, ToolDefinition
from .static_tools import StaticToolRunner


def get_tool_policies() -> dict[str, tuple[str, ...]]:
    return {
        "triage_evidence": ("grep", "find_name", "cat", "sed"),
    }


def _build_providers(context: ToolContext) -> dict[str, object]:
    return {
        "static": StaticToolRunner(
            codebase_path=context.codebase_path,
            timeout_seconds=context.timeout_seconds,
            max_chars=context.max_chars,
        )
    }


def _validate_registry(
    definitions: tuple[ToolDefinition, ...],
    providers: dict[str, object],
) -> None:
    seen_names: set[str] = set()
    for definition in definitions:
        if definition.name in seen_names:
            raise ValueError(f"Duplicate tool name: {definition.name}")
        seen_names.add(definition.name)

        try:
            provider = providers[definition.provider]
        except KeyError as exc:
            raise ValueError(
                f"Unknown tool provider '{definition.provider}' for tool '{definition.name}'"
            ) from exc

        if not hasattr(provider, definition.operation):
            raise ValueError(
                f"Tool '{definition.name}' references missing operation "
                f"'{definition.operation}' on provider '{definition.provider}'"
            )


def _validate_policy_map(
    definitions: tuple[ToolDefinition, ...],
    policies: dict[str, tuple[str, ...]],
) -> None:
    known_names = {definition.name for definition in definitions}
    for policy_name, tool_names in policies.items():
        seen: set[str] = set()
        for tool_name in tool_names:
            if tool_name in seen:
                raise ValueError(
                    f"Policy '{policy_name}' contains duplicate tool '{tool_name}'"
                )
            seen.add(tool_name)
            if tool_name not in known_names:
                raise ValueError(
                    f"Policy '{policy_name}' references unknown tool '{tool_name}'"
                )


def get_tool_definitions() -> tuple[ToolDefinition, ...]:
    return (
        ToolDefinition(
            name="grep",
            domains=tuple(get_tool_policies()),
            provider="static",
            operation="grep",
        ),
        ToolDefinition(
            name="find_name",
            domains=tuple(get_tool_policies()),
            provider="static",
            operation="find_name",
        ),
        ToolDefinition(
            name="cat",
            domains=tuple(get_tool_policies()),
            provider="static",
            operation="cat",
        ),
        ToolDefinition(
            name="sed",
            domains=tuple(get_tool_policies()),
            provider="static",
            operation="sed",
        ),
    )


def build_toolbox(
    *,
    policy: str,
    codebase_path: str,
    timeout_seconds: int = 8,
    max_chars: int = 16000,
) -> ToolBox:
    context = ToolContext(
        codebase_path=codebase_path,
        timeout_seconds=timeout_seconds,
        max_chars=max_chars,
    )
    policies = get_tool_policies()
    definitions = get_tool_definitions()
    if policy not in policies:
        raise ValueError(
            f"Unknown tool policy '{policy}'. Known policies: {', '.join(sorted(policies))}"
        )
    providers = _build_providers(context)
    _validate_registry(definitions, providers)
    _validate_policy_map(definitions, policies)

    allowed = set(policies[policy])
    selected = {
        definition.name: getattr(providers[definition.provider], definition.operation)
        for definition in definitions
        if definition.name in allowed
    }
    return ToolBox(selected)
