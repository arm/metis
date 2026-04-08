# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging

from metis.configuration import load_plugin_config
from metis.exceptions import PluginNotFoundError, QueryEngineInitError
from metis.plugin_loader import discover_supported_language_names, load_plugins
from metis.usage import UsageRuntime
from metis.vector_store.base import BaseVectorStore

from .graphs import AskGraph, ReviewGraph
from .indexing_service import IndexingService
from .repository import EngineRepository
from .review_service import ReviewService
from .runtime import EngineConfig, EngineState
from .triage_constants import DEFAULT_TRIAGE_SIMILARITY_TOP_K
from .triage_service import TriageService

logger = logging.getLogger("metis")


class MetisEngine:
    _SUPPORTED_LANGUAGES = None

    max_workers: int
    max_token_length: int
    llama_query_model: str
    similarity_top_k: int
    response_mode: str

    def __init__(
        self,
        codebase_path=".",
        vector_backend=BaseVectorStore,
        llm_provider=None,
        **kwargs,
    ):
        self.codebase_path = codebase_path
        self.vector_backend = vector_backend

        required_keys = [
            "max_workers",
            "max_token_length",
            "llama_query_model",
            "similarity_top_k",
            "response_mode",
        ]
        missing = [k for k in required_keys if k not in kwargs or kwargs[k] is None]
        if missing:
            raise ValueError(f"Missing required config: {', '.join(missing)}")

        for k in required_keys:
            setattr(self, k, kwargs[k])

        self.llm_provider = llm_provider
        injected_usage_runtime = kwargs.get("usage_runtime")
        self.usage_runtime = self._init_usage_runtime(kwargs)
        self.doc_chunk_size = kwargs.get("doc_chunk_size", 1024)
        self.doc_chunk_overlap = kwargs.get("doc_chunk_overlap", 200)
        self.triage_similarity_top_k = kwargs.get(
            "triage_similarity_top_k", DEFAULT_TRIAGE_SIMILARITY_TOP_K
        )
        self.triage_checkpoint_every = kwargs.get("triage_checkpoint_every", 50)
        self.triage_tool_timeout_seconds = int(
            kwargs.get("triage_tool_timeout_seconds", 12)
        )
        self.custom_prompt_text = kwargs.get("custom_prompt_text")
        self.metisignore_file = kwargs.get("metisignore_file") or ".metisignore"
        self.review_code_include_paths = kwargs.get("review_code_include_paths", [])
        self.review_code_exclude_paths = kwargs.get("review_code_exclude_paths", [])

        self.plugin_config = load_plugin_config()
        self.custom_guidance_precedence = self.plugin_config.get(
            "general_prompts", {}
        ).get("custom_guidance_precedence", "")
        self.plugins = load_plugins(self.plugin_config)

        self.code_exts = set()
        self.ext_plugin_map = {}
        for plugin in self.plugins:
            for extension in plugin.get_supported_extensions():
                lowered = extension.lower()
                self.code_exts.add(lowered)
                self.ext_plugin_map[lowered] = plugin

        self._init_embed_models(injected_usage_runtime)

        self._config = EngineConfig(
            codebase_path=self.codebase_path,
            vector_backend=self.vector_backend,
            llm_provider=self.llm_provider,
            usage_runtime=self.usage_runtime,
            plugin_config=self.plugin_config,
            custom_prompt_text=self.custom_prompt_text,
            custom_guidance_precedence=self.custom_guidance_precedence,
            embed_model_code=self.get_embed_model_code(),
            embed_model_docs=self.get_embed_model_docs(),
            max_workers=self.max_workers,
            max_token_length=self.max_token_length,
            llama_query_model=self.llama_query_model,
            similarity_top_k=self.similarity_top_k,
            response_mode=self.response_mode,
            doc_chunk_size=self.doc_chunk_size,
            doc_chunk_overlap=self.doc_chunk_overlap,
            metisignore_file=self.metisignore_file,
            review_code_include_paths=list(self.review_code_include_paths),
            review_code_exclude_paths=list(self.review_code_exclude_paths),
            code_exts=self.code_exts,
            ext_plugin_map=self.ext_plugin_map,
        )
        self._state = EngineState()
        self.repository = EngineRepository(self._config, self._state)
        self.indexing = IndexingService(
            self._config,
            self._state,
            self.repository,
        )
        self.review = ReviewService(
            self._config,
            self.repository,
            get_query_engines=lambda: self._init_and_get_query_engines(),
            review_graph_factory=lambda: self._get_review_graph(),
        )
        self._triage_service = self._build_triage_service()

    def _init_usage_runtime(self, kwargs) -> UsageRuntime:
        return kwargs.get("usage_runtime") or UsageRuntime(self.codebase_path)

    def _attach_embed_models_to_backend(self) -> None:
        if hasattr(self.vector_backend, "embed_model_code"):
            self.vector_backend.embed_model_code = self._embed_model_code
        if hasattr(self.vector_backend, "embed_model_docs"):
            self.vector_backend.embed_model_docs = self._embed_model_docs

    def _init_embed_models(self, injected_usage_runtime) -> None:
        self._embed_model_code = self._resolve_embed_model(
            "code",
            existing_model=getattr(self.vector_backend, "embed_model_code", None),
            reuse_existing=injected_usage_runtime is not None,
        )
        self._embed_model_docs = self._resolve_embed_model(
            "docs",
            existing_model=getattr(self.vector_backend, "embed_model_docs", None),
            reuse_existing=injected_usage_runtime is not None,
        )
        self._attach_embed_models_to_backend()

    def _build_embed_model(self, kind: str):
        method_name = (
            "get_embed_model_code" if kind == "code" else "get_embed_model_docs"
        )
        method = getattr(self.llm_provider, method_name)
        return method(**self.usage_runtime.hooks.embed_model_kwargs())

    def _resolve_embed_model(
        self,
        kind: str,
        *,
        existing_model=None,
        reuse_existing: bool = False,
    ):
        if reuse_existing and existing_model is not None:
            return existing_model
        return self._build_embed_model(kind)

    def get_embed_model_code(self):
        return self._embed_model_code

    def get_embed_model_docs(self):
        return self._embed_model_docs

    def usage_command(
        self,
        command_name: str,
        target: str | None = None,
        display_name: str | None = None,
    ):
        return self.usage_runtime.command(
            command_name,
            target=target,
            display_name=display_name,
        )

    def finalize_usage_command(self, command) -> dict:
        return self.usage_runtime.finalize_command(command)

    def usage_totals(self) -> dict:
        return self.usage_runtime.snapshot_total()

    def has_usage(self) -> bool:
        return self.usage_runtime.has_usage()

    def save_usage_summary(self, output_path: str | None = None) -> str:
        return self.usage_runtime.save_run_summary(output_path)

    def _build_triage_service(self) -> TriageService:
        return TriageService(
            codebase_path=self.codebase_path,
            llm_provider=self.llm_provider,
            llama_query_model=self.llama_query_model,
            plugin_config=self.plugin_config,
            max_workers=self.max_workers,
            triage_similarity_top_k=self.triage_similarity_top_k,
            triage_checkpoint_every=self.triage_checkpoint_every,
            triage_tool_timeout_seconds=self.triage_tool_timeout_seconds,
            normalize_top_k=self._normalize_top_k,
            create_query_engines=self._create_query_engines,
            get_plugin_for_extension=self._get_plugin_for_extension,
            usage_hooks=self.usage_runtime.hooks,
        )

    def _get_review_graph(self):
        if self._state.review_graph is None:
            self._state.review_graph = ReviewGraph(
                llm_provider=self.llm_provider,
                plugin_config=self.plugin_config,
                custom_prompt_text=self.custom_prompt_text,
                custom_guidance_precedence=self.custom_guidance_precedence,
                llama_query_model=self.llama_query_model,
                max_token_length=self.max_token_length,
                chat_model_kwargs=self.usage_runtime.hooks.chat_model_kwargs(),
            )
        return self._state.review_graph

    def _get_ask_graph(self):
        if self._state.ask_graph is None:
            self._state.ask_graph = AskGraph(
                llm_provider=self.llm_provider,
                llama_query_model=self.llama_query_model,
            )
        return self._state.ask_graph

    @classmethod
    def supported_languages(cls):
        if cls._SUPPORTED_LANGUAGES is None:
            plugin_config = load_plugin_config()
            cls._SUPPORTED_LANGUAGES = discover_supported_language_names(plugin_config)
        return cls._SUPPORTED_LANGUAGES

    def get_plugin_from_name(self, name):
        for plugin in self.plugins:
            if (
                hasattr(plugin, "get_name")
                and plugin.get_name().lower() == name.lower()
            ):
                return plugin
        logger.error(f"Plugin '{name}' not found.")
        raise PluginNotFoundError(name)

    def _get_plugin_for_extension(self, extension):
        return self.repository.get_plugin_for_extension(extension)

    def _get_all_supported_code_extensions(self):
        return self.repository.get_all_supported_code_extensions()

    def _get_splitter_cached(self, plugin):
        return self.repository.get_splitter_cached(plugin)

    def _get_doc_splitter(self):
        return self.repository.get_doc_splitter()

    def _rel_to_base(self, path):
        return self.repository.rel_to_base(path)

    def ask_question(self, question):
        qe_code, qe_docs = self._init_and_get_query_engines()
        logger.info("Querying codebase for your question...")
        req = {
            "question": question,
            "retriever_code": qe_code,
            "retriever_docs": qe_docs,
        }
        return self._get_ask_graph().ask(req)

    def _normalize_top_k(self, value, default: int) -> int:
        try:
            parsed = int(value)
        except Exception:
            parsed = default
        if parsed <= 0:
            return default
        return parsed

    def _create_query_engines(self, top_k: int):
        self.vector_backend.init()
        qe_code, qe_docs = self.vector_backend.get_query_engines(
            self.llm_provider,
            top_k,
            self.response_mode,
            **self.usage_runtime.hooks.query_engine_kwargs(),
        )
        if not qe_code or not qe_docs:
            raise QueryEngineInitError()
        return qe_code, qe_docs

    def _init_and_get_query_engines(self):
        if self._state.qe_code is not None and self._state.qe_docs is not None:
            return self._state.qe_code, self._state.qe_docs
        with self._state.query_engine_lock:
            if self._state.qe_code is not None and self._state.qe_docs is not None:
                return self._state.qe_code, self._state.qe_docs
            top_k = self._normalize_top_k(self.similarity_top_k, 5)
            qe_code, qe_docs = self._create_query_engines(top_k)
            self._state.qe_code = qe_code
            self._state.qe_docs = qe_docs
            return qe_code, qe_docs

    def triage_sarif_payload(
        self,
        payload: dict,
        progress_callback=None,
        debug_callback=None,
        checkpoint_callback=None,
        include_triaged: bool = False,
    ) -> dict:
        return self._triage_service.triage_sarif_payload(
            payload,
            progress_callback=progress_callback,
            debug_callback=debug_callback,
            checkpoint_callback=checkpoint_callback,
            include_triaged=include_triaged,
        )

    def triage_sarif_file(
        self,
        input_path: str,
        output_path: str | None = None,
        progress_callback=None,
        debug_callback=None,
        checkpoint_every: int | None = None,
        include_triaged: bool = False,
    ) -> str:
        return self._triage_service.triage_sarif_file(
            input_path=input_path,
            output_path=output_path,
            progress_callback=progress_callback,
            debug_callback=debug_callback,
            checkpoint_every=checkpoint_every,
            include_triaged=include_triaged,
        )

    def close(self):
        self._state.qe_code = None
        self._state.qe_docs = None
        self._triage_service.close()
        close_fn = getattr(self.vector_backend, "close", None)
        if callable(close_fn):
            close_fn()
