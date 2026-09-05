# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock, RLock, local
from typing import Any

from metis.usage import UsageRuntime
from metis.runtime_settings import CapabilityRuntimeSettings


@dataclass(slots=True)
class EngineConfig:
    codebase_path: str
    vector_backend: Any
    llm_provider: Any
    embedding_provider: Any | None
    usage_runtime: UsageRuntime
    plugin_config: dict[str, Any]
    custom_prompt_text: str | None
    custom_guidance_precedence: str
    max_workers: int
    max_active_nodes: int
    max_concurrent_executions: int
    max_token_length: int
    llama_query_model: str
    chat_model_kwargs: dict[str, Any]
    similarity_top_k: int
    doc_chunk_size: int
    doc_chunk_overlap: int
    metisignore_file: str | None
    review_code_include_paths: list[str]
    review_code_exclude_paths: list[str]
    capability_settings: CapabilityRuntimeSettings
    memory_config: dict[str, Any]
    threat_model_config: dict[str, Any]
    language_registry: Any
    memory_service: Any = None
    code_exts: set[str] = field(default_factory=set)
    ext_plugin_map: dict[str, Any] = field(default_factory=dict)
    ext_pattern_plugin_map: list[tuple[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class EngineState:
    splitter_cache: dict[str, Any] = field(default_factory=dict)
    doc_splitter: Any | None = None
    review_graphs: dict[tuple[bool, str], Any] = field(default_factory=dict)
    ask_graph: Any | None = None
    retriever_code: Any | None = None
    retriever_docs: Any | None = None
    _index_preparation: local = field(default_factory=local, repr=False)
    retriever_lock: RLock = field(default_factory=RLock)
    review_graph_lock: Lock = field(default_factory=Lock)

    @property
    def pending_nodes(self) -> tuple[Any, Any] | None:
        return getattr(self._index_preparation, "nodes", None)

    @pending_nodes.setter
    def pending_nodes(self, value: tuple[Any, Any] | None) -> None:
        self._index_preparation.nodes = value
