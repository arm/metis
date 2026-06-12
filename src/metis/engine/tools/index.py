# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pydantic import BaseModel, Field
from langchain_core.tools import StructuredTool

from ..index_context_service import IndexContextService
from ..repository import EngineRepository
from ..runtime import EngineConfig, EngineState
from .catalog import get_tool_config, get_tool_contract, get_tool_manifest
from .handle import ToolHandle
from .selection import INDEX_TOOL, tool_enabled


class IndexSearchInput(BaseModel):
    query: str = Field(
        description=(
            "Natural-language search query for indexed code and documentation context."
        )
    )
    top_k: int | None = Field(
        default=None,
        description=(
            "Optional number of nearest indexed chunks to retrieve. Runtime caps "
            "come from the index tool YAML config."
        ),
    )
    max_chars: int | None = Field(
        default=None,
        description=(
            "Optional maximum characters to return across code and docs context. "
            "Runtime caps come from the index tool YAML config."
        ),
    )


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

    def search(
        self,
        query: str,
        *,
        top_k: int | None = None,
        max_chars: int | None = None,
    ) -> str:
        return self._handle.require().search(
            query,
            top_k=top_k,
            max_chars=max_chars,
        )

    def langchain_tools(self) -> tuple[StructuredTool, ...]:
        if not self.enabled or not _index_search_model_tool_active():
            return ()
        contract = get_tool_contract(INDEX_TOOL)

        return (
            StructuredTool.from_function(
                func=self.search,
                name="index_search",
                description=(
                    "Search the Metis vector index for relevant code and documentation "
                    "context. Use this when broader project context, related files, "
                    "definitions, APIs, design notes, or documentation may affect the "
                    "answer. Treat results as context candidates and verify security "
                    "claims against concrete source evidence when possible."
                ),
                args_schema=IndexSearchInput,
                metadata={"metis_contract": contract} if contract else None,
            ),
        )

    def model_tool_max_rounds(self) -> int | None:
        if not self.enabled or not _index_search_model_tool_active():
            return None
        model_tool_config = get_tool_config(INDEX_TOOL).get("model_tool") or {}
        if not isinstance(model_tool_config, dict):
            return None
        try:
            max_rounds = int(model_tool_config.get("max_rounds"))
        except (TypeError, ValueError):
            return None
        return max_rounds if max_rounds > 0 else None

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


def _index_search_model_tool_active() -> bool:
    manifest = get_tool_manifest(INDEX_TOOL)
    if manifest is None or not manifest.active:
        return False
    for capability in manifest.capabilities:
        if capability.id == "index.search":
            return capability.status == "active" and "model_tool" in capability.surfaces
    return False
