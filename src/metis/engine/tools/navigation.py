# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from copy import deepcopy
from typing import Any

from langchain_core.tools import StructuredTool

from ..repository import EngineRepository
from ..runtime import EngineConfig, EngineState
from .base import ToolBox
from .catalog import get_tool_config, get_tool_contract, get_tool_manifest
from .handle import ToolHandle
from .registry import build_toolbox
from .selection import NAVIGATION_TOOL, tool_enabled


class NavigationTool:
    name = NAVIGATION_TOOL

    def __init__(self, handle: ToolHandle[ToolBox]):
        self._handle = handle

    @property
    def enabled(self) -> bool:
        return self._handle.enabled

    def grep(self, pattern: str, path: str = ".") -> str:
        return self._handle.require().grep(pattern, path)

    def find_name(self, name: str, max_results: int = 20) -> list[str]:
        return self._handle.require().find_name(name, max_results=max_results)

    def cat(self, path: str) -> str:
        return self._handle.require().cat(path)

    def sed(self, path: str, start_line: int, end_line: int) -> str:
        return self._handle.require().sed(path, start_line, end_line)

    def langchain_tools(self) -> tuple[StructuredTool, ...]:
        if not self.enabled:
            return ()
        metadata = _navigation_model_tool_metadata()
        tools = []
        for capability in _navigation_model_tool_capabilities():
            func = getattr(self, capability.operation or capability.name)
            tools.append(
                StructuredTool.from_function(
                    func=func,
                    name=capability.name,
                    description=capability.description,
                    args_schema=deepcopy(capability.input_schema) or None,
                    metadata=metadata,
                )
            )
        return tuple(tools)

    def has_model_tools(self) -> bool:
        return self.enabled and bool(_navigation_model_tool_capabilities())

    def close(self) -> None:
        self._handle.close()


def build_navigation_tool(
    config: EngineConfig,
    state: EngineState,
    repository: EngineRepository,
) -> NavigationTool:
    del state, repository
    if not tool_enabled(config.enabled_tools, NAVIGATION_TOOL):
        handle: ToolHandle[ToolBox] = ToolHandle(NAVIGATION_TOOL, None)
        return NavigationTool(handle)

    tool_config = _navigation_model_tool_config()
    toolbox = build_toolbox(
        policy="triage_evidence",
        codebase_path=config.codebase_path,
        timeout_seconds=_positive_int(tool_config.get("timeout_seconds"), 8),
        max_chars=_positive_int(tool_config.get("max_chars"), 16000),
    )
    return NavigationTool(ToolHandle(NAVIGATION_TOOL, toolbox))


def _navigation_model_tool_capabilities():
    manifest = get_tool_manifest(NAVIGATION_TOOL)
    if manifest is None or not manifest.active:
        return ()
    return tuple(
        capability
        for capability in manifest.capabilities
        if capability.status == "active" and "model_tool" in capability.surfaces
    )


def _navigation_model_tool_metadata() -> dict[str, object] | None:
    contract = get_tool_contract(NAVIGATION_TOOL)
    if not contract:
        return None
    metadata: dict[str, object] = {"metis_contract": contract}
    max_contract_chars = _positive_int(
        _navigation_model_tool_config().get("max_contract_chars"),
        0,
    )
    if max_contract_chars > 0:
        metadata["metis_contract_max_chars"] = max_contract_chars
    return metadata


def _navigation_model_tool_config() -> dict[str, Any]:
    config = get_tool_config(NAVIGATION_TOOL).get("model_tool") or {}
    if isinstance(config, dict):
        return config
    return {}


def _positive_int(value: object, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if parsed <= 0:
        return default
    return parsed
