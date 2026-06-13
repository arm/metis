# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from .catalog import get_tool_manifest
from .base import ToolBox, ToolContext, ToolDefinition
from .static_tools import StaticToolRunner


def get_tool_policies() -> dict[str, tuple[str, ...]]:
    policies: dict[str, list[str]] = {}
    for definition in get_tool_definitions():
        for domain in definition.domains:
            policies.setdefault(domain, []).append(definition.name)
    return {name: tuple(tools) for name, tools in sorted(policies.items())}


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
    manifest = get_tool_manifest("navigation")
    if manifest is None:
        return ()
    definitions = []
    for capability in manifest.capabilities:
        if capability.status != "active":
            continue
        if not capability.provider or not capability.operation:
            continue
        definitions.append(
            ToolDefinition(
                name=capability.name,
                domains=capability.domains,
                provider=capability.provider,
                operation=capability.operation,
            )
        )
    return tuple(definitions)


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
