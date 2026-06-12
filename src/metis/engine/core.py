# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging

from metis.chat_model_options import merge_chat_model_kwargs
from metis.configuration import load_plugin_config
from metis.exceptions import PluginNotFoundError
from metis.plugins.registry import LanguagePluginRegistry
from metis.reachability_settings import coerce_reachability_settings
from metis.usage import UsageRuntime
from metis.vector_store.base import BaseVectorStore

from .graphs import AskGraph, ReviewGraph
from .options import TriageOptions
from .reachability.service import TreeSitterReachabilityService
from .repository import EngineRepository
from .review_service import ReviewService
from .runtime import EngineConfig, EngineState
from .tools.engine import build_engine_tools
from .tools.selection import parse_engine_tools
from .triage_constants import DEFAULT_TRIAGE_SIMILARITY_TOP_K
from .triage_service import TriageService

logger = logging.getLogger("metis")


class MetisEngine:
    _SUPPORTED_LANGUAGES = None

    max_workers: int
    max_token_length: int
    llama_query_model: str
    similarity_top_k: int

    def __init__(
        self,
        codebase_path=".",
        vector_backend=BaseVectorStore,
        llm_provider=None,
        embedding_provider=None,
        **kwargs,
    ):
        self.codebase_path = codebase_path
        self.vector_backend = vector_backend

        required_keys = [
            "max_workers",
            "max_token_length",
            "llama_query_model",
            "similarity_top_k",
        ]
        missing = [k for k in required_keys if k not in kwargs or kwargs[k] is None]
        if missing:
            raise ValueError(f"Missing required config: {', '.join(missing)}")

        for k in required_keys:
            setattr(self, k, kwargs[k])

        self.llm_provider = llm_provider
        self.usage_runtime = self._init_usage_runtime(kwargs)
        self.chat_model_kwargs = dict(kwargs.get("chat_model_kwargs") or {})
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
        self.enabled_tools = parse_engine_tools(kwargs.get("enabled_tools"))
        self.reachability_settings = coerce_reachability_settings(
            kwargs, default_workers=self.max_workers
        )

        self.plugin_config = load_plugin_config()
        self.custom_guidance_precedence = self.plugin_config.get(
            "general_prompts", {}
        ).get("custom_guidance_precedence", "")
        self.language_registry = LanguagePluginRegistry.from_config(self.plugin_config)
        self.code_exts = set(self.language_registry.supported_code_extensions())

        self._config = EngineConfig(
            codebase_path=self.codebase_path,
            vector_backend=self.vector_backend,
            llm_provider=self.llm_provider,
            embedding_provider=embedding_provider,
            usage_runtime=self.usage_runtime,
            plugin_config=self.plugin_config,
            custom_prompt_text=self.custom_prompt_text,
            custom_guidance_precedence=self.custom_guidance_precedence,
            max_workers=self.max_workers,
            max_token_length=self.max_token_length,
            llama_query_model=self.llama_query_model,
            chat_model_kwargs=self.chat_model_kwargs,
            similarity_top_k=self.similarity_top_k,
            doc_chunk_size=self.doc_chunk_size,
            doc_chunk_overlap=self.doc_chunk_overlap,
            metisignore_file=self.metisignore_file,
            review_code_include_paths=list(self.review_code_include_paths),
            review_code_exclude_paths=list(self.review_code_exclude_paths),
            enabled_tools=self.enabled_tools,
            language_registry=self.language_registry,
            code_exts=self.code_exts,
        )
        self._state = EngineState()
        self.repository = EngineRepository(self._config, self._state)
        self.tools = build_engine_tools(
            self._config,
            self._state,
            self.repository,
        )
        self.index_context = self.tools.index
        self.reachability = TreeSitterReachabilityService(
            config=self._config,
            repository=self.repository,
            llm_provider=self.llm_provider,
            usage_runtime=self.usage_runtime,
        )
        self.review = ReviewService(
            self._config,
            self.repository,
            get_retrievers=lambda: self.tools.index.get_retrievers(),
            review_graph_factory=lambda: self._get_review_graph(),
            reachability_service=self.reachability,
            reachability_settings=self.reachability_settings,
        )
        self._triage_service = self._build_triage_service()

    def _init_usage_runtime(self, kwargs) -> UsageRuntime:
        return kwargs.get("usage_runtime") or UsageRuntime(self.codebase_path)

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
            chat_model_kwargs=self.chat_model_kwargs,
            plugin_config=self.plugin_config,
            max_workers=self.max_workers,
            triage_similarity_top_k=self.triage_similarity_top_k,
            triage_checkpoint_every=self.triage_checkpoint_every,
            triage_tool_timeout_seconds=self.triage_tool_timeout_seconds,
            create_retrievers=self.tools.index.create_retrievers,
            get_plugin_for_path=self.repository.get_plugin_for_path,
            get_language_name_for_path=self.repository.get_language_name_for_path,
            usage_hooks=self.usage_runtime.hooks,
        )

    @property
    def indexing(self):
        return self.tools.index.indexing

    def _get_review_graph(self):
        if self._state.review_graph is None:
            self._state.review_graph = ReviewGraph(
                llm_provider=self.llm_provider,
                plugin_config=self.plugin_config,
                custom_prompt_text=self.custom_prompt_text,
                custom_guidance_precedence=self.custom_guidance_precedence,
                llama_query_model=self.llama_query_model,
                max_token_length=self.max_token_length,
                chat_model_kwargs=self._chat_model_kwargs(),
            )
        return self._state.review_graph

    def _chat_model_kwargs(self) -> dict:
        return merge_chat_model_kwargs(
            self.chat_model_kwargs,
            self.usage_runtime.hooks.chat_model_kwargs(),
        )

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
            registry = LanguagePluginRegistry.from_config(plugin_config)
            cls._SUPPORTED_LANGUAGES = registry.supported_language_names()
        return cls._SUPPORTED_LANGUAGES

    def get_plugin_from_name(self, name):
        plugin = self.language_registry.get_plugin(name)
        if plugin is not None:
            return plugin
        logger.error(f"Plugin '{name}' not found.")
        raise PluginNotFoundError(name)

    def ask_question(self, question):
        retriever_code, retriever_docs = self.tools.index.get_retrievers()
        logger.info("Querying codebase for your question...")
        req = {
            "question": question,
            "retriever_code": retriever_code,
            "retriever_docs": retriever_docs,
        }
        return self._get_ask_graph().ask(req)

    def _create_retrievers(self, top_k: int):
        return self.tools.index.create_retrievers(top_k)

    def _init_and_get_retrievers(self):
        return self.tools.index.get_retrievers()

    def triage_sarif_payload(
        self,
        payload: dict,
        progress_callback=None,
        debug_callback=None,
        checkpoint_callback=None,
        options: TriageOptions | None = None,
    ) -> dict:
        return self._triage_service.triage_sarif_payload(
            payload,
            progress_callback=progress_callback,
            debug_callback=debug_callback,
            checkpoint_callback=checkpoint_callback,
            options=options,
        )

    def triage_sarif_file(
        self,
        input_path: str,
        output_path: str | None = None,
        progress_callback=None,
        debug_callback=None,
        checkpoint_every: int | None = None,
        options: TriageOptions | None = None,
    ) -> str:
        return self._triage_service.triage_sarif_file(
            input_path=input_path,
            output_path=output_path,
            progress_callback=progress_callback,
            debug_callback=debug_callback,
            checkpoint_every=checkpoint_every,
            options=options,
        )

    def close(self):
        self.tools.index.clear_retriever_cache()
        self._triage_service.close()
        self.tools.close()
