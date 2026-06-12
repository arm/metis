# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.exceptions import RetrieverInitError
from metis.vector_store.retrievers import document_text
from metis.vector_store.retrievers import retrieve_documents

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

    def search(
        self,
        query: str,
        *,
        top_k: int | None = None,
        max_chars: int | None = None,
    ) -> str:
        query = str(query or "").strip()
        if not query:
            return "[INDEX_SEARCH_ERROR]\nquery is required."

        search_config = _index_search_config(self._config)
        requested_top_k = normalize_top_k(top_k, search_config["default_top_k"])
        effective_top_k = min(requested_top_k, search_config["max_top_k"])
        requested_max_chars = normalize_top_k(
            max_chars, search_config["default_max_chars"]
        )
        effective_max_chars = min(requested_max_chars, search_config["max_chars"])

        default_top_k = normalize_top_k(self._config.similarity_top_k, 5)
        if effective_top_k == default_top_k:
            retriever_code, retriever_docs = self.get_retrievers()
        else:
            retriever_code, retriever_docs = self.create_retrievers(effective_top_k)

        code_text = _retrieve_index_text(
            retriever_code,
            query,
            max_chars=effective_max_chars // 2,
        )
        docs_text = _retrieve_index_text(
            retriever_docs,
            query,
            max_chars=effective_max_chars // 2,
        )
        sections = [f"[INDEX_SEARCH]\nquery: {query}\ntop_k: {effective_top_k}"]
        if code_text:
            sections.extend(["[CODE_CONTEXT]", code_text])
        if docs_text:
            sections.extend(["[DOC_CONTEXT]", docs_text])
        if not code_text and not docs_text:
            sections.append("No relevant indexed context returned.")
        return "\n\n".join(sections)

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


def _index_search_config(config: EngineConfig) -> dict[str, int]:
    from .tools.catalog import get_tool_config
    from .tools.selection import INDEX_TOOL

    tool_config = get_tool_config(INDEX_TOOL)
    search = tool_config.get("search") or {}
    if not isinstance(search, dict):
        search = {}

    default_top_k = normalize_top_k(
        search.get("default_top_k"),
        normalize_top_k(config.similarity_top_k, 5),
    )
    max_top_k = normalize_top_k(search.get("max_top_k"), default_top_k)
    max_chars = _required_positive_int(search, "max_chars")
    default_max_chars = _positive_int(
        search.get("default_max_chars"),
        fallback=max_chars,
    )
    return {
        "default_top_k": default_top_k,
        "max_top_k": max_top_k,
        "default_max_chars": default_max_chars,
        "max_chars": max_chars,
    }


def _required_positive_int(values: dict[str, object], key: str) -> int:
    value = values.get(key)
    parsed = _positive_int(value, fallback=0)
    if parsed <= 0:
        raise ValueError(f"Index search config requires positive '{key}'")
    return parsed


def _positive_int(value: object, *, fallback: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return fallback
    if parsed <= 0:
        return fallback
    return parsed
