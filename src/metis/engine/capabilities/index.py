# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import model_validator

from metis.exceptions import RetrieverInitError
from metis.engine.repository import EngineRepository
from metis.engine.runtime import EngineConfig, EngineState
from metis.vector_store.retrievers import document_text
from metis.vector_store.retrievers import retrieve_documents

from .indexing import IndexingService


class IndexSearchConfiguration(BaseModel):
    max_top_k: int = Field(gt=0)
    code_top_k: int = Field(gt=0)
    docs_top_k: int = Field(gt=0)
    docs_char_ratio: float = Field(ge=0.0, le=1.0)
    default_max_chars: int = Field(gt=0)
    max_chars: int = Field(gt=0)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_character_limits(self) -> "IndexSearchConfiguration":
        if self.default_max_chars > self.max_chars:
            raise ValueError("default_max_chars must not exceed max_chars")
        return self


class IndexCapabilityConfiguration(BaseModel):
    search: IndexSearchConfiguration

    model_config = ConfigDict(extra="forbid", frozen=True)


def normalize_top_k(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


class IndexCapability:
    name = "index"

    def __init__(
        self,
        config: EngineConfig,
        state: EngineState,
        repository: EngineRepository,
        search_configuration: IndexSearchConfiguration,
    ) -> None:
        self._config = config
        self._state = state
        self._search_configuration = search_configuration
        self._embed_model_code = self._get_backend_embed_model("embed_model_code")
        self._embed_model_docs = self._get_backend_embed_model("embed_model_docs")
        self._retrievers_by_top_k: dict[int, tuple[Any, Any]] = {}
        self._retriever_generation = 0
        self._constructing_embeddings = False
        self._attach_embed_models_to_backend()
        self.indexing = IndexingService(
            config,
            state,
            repository,
            get_embedding_models=self.get_embedding_models,
            clear_retriever_cache=self.clear_retriever_cache,
        )

    def create_retrievers(self, top_k: int):
        with self._state.retriever_lock:
            generation = self._retriever_generation
            self.get_embedding_models()
            self._config.vector_backend.init()
            retriever_code, retriever_docs = self._config.vector_backend.get_retrievers(
                self._config.llm_provider,
                top_k,
                **self._config.usage_runtime.hooks.retriever_kwargs(),
            )
            # A backend callback may have reset the index on this thread.
            if generation != self._retriever_generation:
                raise RuntimeError("Index changed during retriever construction")
            if not retriever_code or not retriever_docs:
                raise RetrieverInitError()
            return retriever_code, retriever_docs

    def get_retrievers(self):
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

    def search(
        self,
        query: str,
        *,
        top_k: int | None = None,
        max_chars: int | None = None,
        source: str | None = None,
    ) -> str:
        query = str(query or "").strip()
        if not query:
            return "[INDEX_SEARCH_ERROR]\nquery is required."

        search_config = self._search_configuration
        max_top_k = search_config.max_top_k
        code_top_k = min(search_config.code_top_k, max_top_k)
        docs_top_k = min(search_config.docs_top_k, max_top_k)
        requested_max_chars = normalize_top_k(
            max_chars, search_config.default_max_chars
        )
        effective_max_chars = min(requested_max_chars, search_config.max_chars)
        source = _normalize_source(source)
        code_chars, docs_chars = _split_source_budget(
            source,
            total_chars=effective_max_chars,
            docs_ratio=search_config.docs_char_ratio,
        )

        code_text = ""
        docs_text = ""
        if code_chars > 0:
            retriever_code, _ = self._retrievers_for_top_k(code_top_k)
            code_text = _retrieve_index_text(
                retriever_code,
                query,
                max_chars=code_chars,
            )
        if docs_chars > 0:
            _, retriever_docs = self._retrievers_for_top_k(docs_top_k)
            docs_text = _retrieve_index_text(
                retriever_docs,
                query,
                max_chars=docs_chars,
            )

        sections = [
            (
                f"[INDEX_SEARCH]\nquery: {query}\nsource: {source}"
                f"\ncode_top_k: {code_top_k}\ndocs_top_k: {docs_top_k}"
            )
        ]
        if code_text:
            sections.extend(["[CODE_CONTEXT]", code_text])
        if docs_text:
            sections.extend(["[DOC_CONTEXT]", docs_text])
        if not code_text and not docs_text:
            sections.append("No relevant indexed context returned.")
        return "\n\n".join(sections)

    def supports_search(self) -> bool:
        has_cached_retrievers = (
            self._state.retriever_code is not None
            and self._state.retriever_docs is not None
        )
        has_embedding_models = (
            self._embed_model_code is not None and self._embed_model_docs is not None
        )
        return bool(
            has_cached_retrievers
            or has_embedding_models
            or self._config.embedding_provider is not None
        )

    def clear_retriever_cache(self) -> None:
        with self._state.retriever_lock:
            self._state.retriever_code = None
            self._state.retriever_docs = None
            self._retrievers_by_top_k.clear()
            self._retriever_generation += 1

    def close(self) -> None:
        try:
            self.indexing.close()
        finally:
            self.clear_retriever_cache()

    def get_embedding_models(self):
        with self._state.retriever_lock:
            if self._constructing_embeddings:
                raise RuntimeError(
                    "Index embedding models are already being constructed"
                )
            self._constructing_embeddings = True
            try:
                code, docs = self._embed_model_code, self._embed_model_docs
                if code is None:
                    code = self._build_embed_model("code")
                if docs is None:
                    docs = self._build_embed_model("docs")
                self._embed_model_code, self._embed_model_docs = code, docs
                self._attach_embed_models_to_backend()
                return code, docs
            finally:
                self._constructing_embeddings = False

    def _build_embed_model(self, kind: str):
        provider = self._config.embedding_provider
        if provider is None:
            raise RuntimeError(
                "Index capability requires embedding_provider configuration."
            )
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

    def _retrievers_for_top_k(self, top_k: int):
        default_top_k = normalize_top_k(self._config.similarity_top_k, 5)
        if top_k == default_top_k:
            return self.get_retrievers()
        with self._state.retriever_lock:
            retrievers = self._retrievers_by_top_k.get(top_k)
            if retrievers is None:
                retrievers = self.create_retrievers(top_k)
                self._retrievers_by_top_k[top_k] = retrievers
            return retrievers


def _retrieve_index_text(retriever, query: str, *, max_chars: int) -> str:
    try:
        documents = retrieve_documents(retriever, query)
    except Exception as exc:
        return f"[INDEX_RETRIEVAL_ERROR]\n{exc}"

    parts = []
    total = 0
    for document in documents or []:
        text = document_text(document).strip()
        if not text:
            continue
        remaining = max_chars - total
        if remaining <= 0:
            break
        if len(text) > remaining:
            parts.append(text[:remaining].rstrip() + "\n[truncated]")
            break
        parts.append(text)
        total += len(text)
    return "\n\n".join(parts)


def _normalize_source(value: str | None) -> str:
    source = str(value or "both").strip().lower()
    if source in {"code", "docs", "both"}:
        return source
    return "both"


def _split_source_budget(
    source: str,
    *,
    total_chars: int,
    docs_ratio: float,
) -> tuple[int, int]:
    if source == "code":
        return total_chars, 0
    if source == "docs":
        return 0, total_chars
    if total_chars <= 1:
        return total_chars, 0
    if docs_ratio <= 0:
        return total_chars, 0
    if docs_ratio >= 1:
        return 0, total_chars
    docs_chars = round(total_chars * docs_ratio)
    docs_chars = min(max(docs_chars, 1), total_chars - 1)
    return total_chars - docs_chars, docs_chars
