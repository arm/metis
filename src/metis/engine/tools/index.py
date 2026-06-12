# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from copy import deepcopy
from typing import Any

from langchain_core.tools import StructuredTool

from ..index_context_service import IndexContextService
from ..repository import EngineRepository
from ..runtime import EngineConfig, EngineState
from .catalog import get_tool_config, get_tool_contract, get_tool_manifest
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
        capability = _index_search_model_tool_capability()
        if not self.enabled or capability is None:
            return ()
        contract = get_tool_contract(INDEX_TOOL)
        metadata: dict[str, object] | None = None
        if contract:
            metadata = {"metis_contract": contract}
            max_contract_chars = _positive_int(
                _index_model_tool_config().get("max_contract_chars")
            )
            if max_contract_chars is not None:
                metadata["metis_contract_max_chars"] = max_contract_chars

        return (
            StructuredTool.from_function(
                func=self.search,
                name=capability.name,
                description=capability.description,
                args_schema=deepcopy(capability.input_schema) or None,
                metadata=metadata,
            ),
        )

    def has_model_tools(self) -> bool:
        return self.enabled and _index_search_model_tool_capability() is not None

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


def _index_search_model_tool_capability():
    manifest = get_tool_manifest(INDEX_TOOL)
    if manifest is None or not manifest.active:
        return None
    for capability in manifest.capabilities:
        if capability.id == "index.search":
            if capability.status == "active" and "model_tool" in capability.surfaces:
                return capability
            return None
    return None


def _index_model_tool_config() -> dict[str, Any]:
    config = get_tool_config(INDEX_TOOL).get("model_tool") or {}
    if isinstance(config, dict):
        return config
    return {}


def _positive_int(value: object) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    return parsed
