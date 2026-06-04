# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..index_context_service import IndexContextService
from ..repository import EngineRepository
from ..runtime import EngineConfig, EngineState
from .handle import ToolHandle
from .selection import INDEX_TOOL, tool_enabled


class IndexTool:
    name = INDEX_TOOL

    def __init__(self, handle: ToolHandle[IndexContextService]):
        self._handle = handle

    @property
    def enabled(self) -> bool:
        return self._handle.enabled

    @property
    def indexing(self):
        return self._handle.require().indexing

    def create_query_engines(self, top_k: int):
        return self._handle.require().create_query_engines(top_k)

    def get_query_engines(self):
        return self._handle.require().get_query_engines()

    def clear_query_cache(self) -> None:
        if self.enabled:
            self._handle.require().clear_query_cache()

    def close(self) -> None:
        self._handle.close()


def build_index_tool(
    config: EngineConfig,
    state: EngineState,
    repository: EngineRepository,
    *,
    normalize_top_k: Callable[[Any, int], int],
) -> IndexTool:
    if not tool_enabled(config.enabled_tools, INDEX_TOOL):
        handle: ToolHandle[IndexContextService] = ToolHandle(INDEX_TOOL, None)
        return IndexTool(handle)

    service = IndexContextService(
        config,
        state,
        repository,
        normalize_top_k=normalize_top_k,
    )
    return IndexTool(ToolHandle(INDEX_TOOL, service))
