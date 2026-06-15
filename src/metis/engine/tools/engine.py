# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass

from ..repository import EngineRepository
from ..runtime import EngineConfig, EngineState
from .index import IndexTool, build_index_tool
from .navigation import NavigationTool, build_navigation_tool


@dataclass(frozen=True, slots=True)
class EngineTools:
    config: EngineConfig
    index: IndexTool
    navigation: NavigationTool

    def langchain_tools(self) -> tuple[object, ...]:
        return (*self.index.langchain_tools(),)

    def triage_langchain_tools(self) -> tuple[object, ...]:
        return (*self.navigation.langchain_tools(),)

    def model_tool_max_rounds(self) -> int | None:
        if not self.index.has_model_tools():
            return None
        return self.config.model_tool_max_rounds

    def triage_model_tool_max_rounds(self) -> int | None:
        if not self.navigation.has_model_tools():
            return None
        return self.config.model_tool_max_rounds

    def close(self) -> None:
        self.index.close()
        self.navigation.close()


def build_engine_tools(
    config: EngineConfig,
    state: EngineState,
    repository: EngineRepository,
) -> EngineTools:
    return EngineTools(
        config=config,
        index=build_index_tool(
            config,
            state,
            repository,
        ),
        navigation=build_navigation_tool(
            config,
            state,
            repository,
        ),
    )
