# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from metis.usage import UsageRuntime


@dataclass(slots=True)
class EngineConfig:
    codebase_path: str
    vector_backend: Any
    llm_provider: Any
    usage_runtime: UsageRuntime
    plugin_config: dict[str, Any]
    custom_prompt_text: str | None
    custom_guidance_precedence: str
    embed_model_code: Any
    embed_model_docs: Any
    max_workers: int
    max_token_length: int
    llama_query_model: str
    similarity_top_k: int
    response_mode: str
    doc_chunk_size: int
    doc_chunk_overlap: int
    metisignore_file: str | None
    review_code_include_paths: list[str]
    review_code_exclude_paths: list[str]
    code_exts: set[str] = field(default_factory=set)
    ext_plugin_map: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EngineState:
    splitter_cache: dict[str, Any] = field(default_factory=dict)
    doc_splitter: Any | None = None
    review_graph: Any | None = None
    ask_graph: Any | None = None
    qe_code: Any | None = None
    qe_docs: Any | None = None
    pending_nodes: tuple[Any, Any] | None = None
    query_engine_lock: Lock = field(default_factory=Lock)
