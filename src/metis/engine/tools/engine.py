# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass

from ..repository import EngineRepository
from ..runtime import EngineConfig, EngineState
from .index import IndexTool, build_index_tool


@dataclass(frozen=True, slots=True)
class EngineTools:
    index: IndexTool

    def langchain_tools(self) -> tuple[object, ...]:
        return (*self.index.langchain_tools(),)

    def model_tool_max_rounds(self) -> int | None:
        return self.index.model_tool_max_rounds()

    def close(self) -> None:
        self.index.close()


def build_engine_tools(
    config: EngineConfig,
    state: EngineState,
    repository: EngineRepository,
) -> EngineTools:
    return EngineTools(
        index=build_index_tool(
            config,
            state,
            repository,
        )
    )
