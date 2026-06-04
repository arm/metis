# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..repository import EngineRepository
from ..runtime import EngineConfig, EngineState
from .index import IndexTool, build_index_tool


@dataclass(frozen=True, slots=True)
class EngineTools:
    index: IndexTool

    def close(self) -> None:
        self.index.close()


def build_engine_tools(
    config: EngineConfig,
    state: EngineState,
    repository: EngineRepository,
    *,
    normalize_top_k: Callable[[Any, int], int],
) -> EngineTools:
    return EngineTools(
        index=build_index_tool(
            config,
            state,
            repository,
            normalize_top_k=normalize_top_k,
        )
    )
