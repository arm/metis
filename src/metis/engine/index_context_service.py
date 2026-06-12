# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.exceptions import RetrieverInitError

from .indexing_service import IndexingService
from .options import normalize_top_k
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
    ):
        self._config = config
        self._state = state
        self._embed_model_code = self._get_backend_embed_model("embed_model_code")
        self._embed_model_docs = self._get_backend_embed_model("embed_model_docs")
        self._attach_embed_models_to_backend()
        self.indexing = IndexingService(
            config,
            state,
            repository,
            get_embedding_models=self.get_embedding_models,
        )

    def create_retrievers(self, top_k: int):
        self.get_embedding_models()
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
            top_k = normalize_top_k(self._config.similarity_top_k, 5)
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

    def get_embedding_models(self):
        if self._embed_model_code is None:
            self._embed_model_code = self._build_embed_model("code")
        if self._embed_model_docs is None:
            self._embed_model_docs = self._build_embed_model("docs")
        self._attach_embed_models_to_backend()
        return self._embed_model_code, self._embed_model_docs

    def _build_embed_model(self, kind: str):
        provider = self._config.embedding_provider
        if provider is None:
            raise RuntimeError("Index tool requires embedding_provider configuration.")
        method_name = (
            "get_embed_model_code" if kind == "code" else "get_embed_model_docs"
        )
        method = getattr(provider, method_name)
        return method(**self._config.usage_runtime.hooks.embed_model_kwargs())

    def _attach_embed_models_to_backend(self) -> None:
        if hasattr(self._config.vector_backend, "embed_model_code"):
            self._config.vector_backend.embed_model_code = self._embed_model_code
        if hasattr(self._config.vector_backend, "embed_model_docs"):
            self._config.vector_backend.embed_model_docs = self._embed_model_docs

    def _get_backend_embed_model(self, attr: str):
        if attr in getattr(self._config.vector_backend, "__dict__", {}):
            return getattr(self._config.vector_backend, attr)
        return None
