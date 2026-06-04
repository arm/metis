# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from metis.exceptions import QueryEngineInitError

from .indexing_service import IndexingService
from .repository import EngineRepository
from .runtime import EngineConfig, EngineState


class IndexContextService:
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

    def create_query_engines(self, top_k: int):
        self._config.vector_backend.init()
        qe_code, qe_docs = self._config.vector_backend.get_query_engines(
            self._config.llm_provider,
            top_k,
            self._config.response_mode,
            **self._config.usage_runtime.hooks.query_engine_kwargs(),
        )
        if not qe_code or not qe_docs:
            raise QueryEngineInitError()
        return qe_code, qe_docs

    def get_query_engines(self):
        if self._state.qe_code is not None and self._state.qe_docs is not None:
            return self._state.qe_code, self._state.qe_docs
        with self._state.query_engine_lock:
            if self._state.qe_code is not None and self._state.qe_docs is not None:
                return self._state.qe_code, self._state.qe_docs
            top_k = self._normalize_top_k(self._config.similarity_top_k, 5)
            qe_code, qe_docs = self.create_query_engines(top_k)
            self._state.qe_code = qe_code
            self._state.qe_docs = qe_docs
            return qe_code, qe_docs

    def clear_query_cache(self) -> None:
        self._state.qe_code = None
        self._state.qe_docs = None

    def close(self) -> None:
        self.clear_query_cache()
        close_fn = getattr(self._config.vector_backend, "close", None)
        if callable(close_fn):
            close_fn()
