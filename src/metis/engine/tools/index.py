# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

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

    def create_retrievers(self, top_k: int):
        return self._handle.require().create_retrievers(top_k)

    def get_retrievers(self):
        return self._handle.require().get_retrievers()

    def get_embedding_models(self):
        return self._handle.require().get_embedding_models()

    def clear_retriever_cache(self) -> None:
        if self.enabled:
            self._handle.require().clear_retriever_cache()

    def close(self) -> None:
        self._handle.close()


def build_index_tool(
    config: EngineConfig,
    state: EngineState,
    repository: EngineRepository,
) -> IndexTool:
    if not tool_enabled(config.enabled_tools, INDEX_TOOL):
        handle: ToolHandle[IndexContextService] = ToolHandle(INDEX_TOOL, None)
        return IndexTool(handle)

    service = IndexContextService(
        config,
        state,
        repository,
    )
    return IndexTool(ToolHandle(INDEX_TOOL, service))
