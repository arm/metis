# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from metis.exceptions import RetrieverInitError

from .indexing_service import IndexingService
from .repository import EngineRepository
from .runtime import EngineConfig, EngineState


class IndexContextService:
    name = "index"
    enabled = True

    def __init__(
        self,
        config: EngineConfig,
        state: EngineState,
        repository: EngineRepository,
        *,
        normalize_top_k: Callable[[Any, int], int],
    ):
        self._config = config
        self._state = state
        self._normalize_top_k = normalize_top_k
        self.indexing = IndexingService(config, state, repository)

    def create_retrievers(self, top_k: int):
        self._ensure_embed_models()
        self._config.vector_backend.init()
        retriever_code, retriever_docs = self._config.vector_backend.get_retrievers(
            self._config.llm_provider,
            top_k,
            **self._config.usage_runtime.hooks.retriever_kwargs(),
        )
        if not retriever_code or not retriever_docs:
            raise RetrieverInitError()
        return retriever_code, retriever_docs

    def get_retrievers(self):
        if (
            self._state.retriever_code is not None
            and self._state.retriever_docs is not None
        ):
            return self._state.retriever_code, self._state.retriever_docs
        with self._state.retriever_lock:
            if (
                self._state.retriever_code is not None
                and self._state.retriever_docs is not None
            ):
                return self._state.retriever_code, self._state.retriever_docs
            top_k = self._normalize_top_k(self._config.similarity_top_k, 5)
            retriever_code, retriever_docs = self.create_retrievers(top_k)
            self._state.retriever_code = retriever_code
            self._state.retriever_docs = retriever_docs
            return retriever_code, retriever_docs

    def clear_retriever_cache(self) -> None:
        self._state.retriever_code = None
        self._state.retriever_docs = None

    def close(self) -> None:
        self.clear_retriever_cache()
        close_fn = getattr(self._config.vector_backend, "close", None)
        if callable(close_fn):
            close_fn()

    def _ensure_embed_models(self) -> None:
        self._config.embed_model_code = self._config.engine_get_embed_model_code()
        self._config.embed_model_docs = self._config.engine_get_embed_model_docs()
