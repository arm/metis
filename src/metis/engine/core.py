# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from typing import cast
from typing import Literal

from metis.chat_model_options import merge_chat_model_kwargs
from metis.configuration import load_execution_config
from metis.configuration import load_plugin_config
from metis.plugins.c_family.codegraph import CFamilyCodeGraphProvider
from metis.plugins.c_family.semantics import CFamilyCodeGraphSemantics
from metis.plugins.registry import LanguagePluginRegistry
from metis.usage import UsageRuntime
from metis.runlog import RunLogSession
from metis.runlog import bind_runlog
from metis import runlog
from metis.vector_store.base import BaseVectorStore

from .ask import AskGraph
from .execution import ExecutionResult
from .execution import ExecutionStatus
from .nodes.codegraph import CodeGraphConfiguration
from .codegraph import CodeGraphReference
from .nodes.codegraph import CodeGraphService
from .nodes.codegraph.provider import discover_provider_factories
from .nodes.codegraph.semantics import CodeGraphSemanticsCatalog
from .nodes.builtins import build_builtin_execution
from .capabilities.indexing import IndexingService
from .nodes.reachability.options import ReachabilityConfiguration
from .nodes.simple_llm_review.graph import ReviewGraph
from .repository import EngineRepository
from .runtime import EngineConfig, EngineState
from .stages.configuration import ExecutionConfiguration
from .stages.review.models import ReviewCommand
from metis.runtime_settings import CapabilityRuntimeSettings
from metis.runtime_settings import TriageOptions
from .capabilities.engine import build_engine_capabilities
from .capabilities.builtins import builtin_capability_registrations
from .capabilities.catalog import CapabilityCatalog
from .capabilities.contracts import CapabilityContext
from .capabilities.index import IndexCapability
from .tools.index import index_model_tools

logger = logging.getLogger("metis")


class MetisEngine:
    def __init__(
        self,
        codebase_path: str = ".",
        vector_backend: Any = BaseVectorStore,
        llm_provider: Any = None,
        embedding_provider: Any = None,
        runlog: RunLogSession | None = None,
        **kwargs: Any,
    ) -> None:
        self.codebase_path = codebase_path
        self._runlog = runlog

        required_keys = [
            "max_workers",
            "max_token_length",
            "llama_query_model",
            "similarity_top_k",
            "capability_settings",
        ]
        missing = [k for k in required_keys if k not in kwargs or kwargs[k] is None]
        if missing:
            raise ValueError(f"Missing required config: {', '.join(missing)}")

        max_workers = cast(int, kwargs["max_workers"])
        max_token_length = cast(int, kwargs["max_token_length"])
        llama_query_model = cast(str, kwargs["llama_query_model"])
        similarity_top_k = cast(int, kwargs["similarity_top_k"])
        capability_settings = cast(
            CapabilityRuntimeSettings, kwargs["capability_settings"]
        )
        usage_runtime = cast(
            UsageRuntime,
            kwargs.get("usage_runtime") or UsageRuntime(self.codebase_path),
        )
        chat_model_kwargs = dict(kwargs.get("chat_model_kwargs") or {})
        triage_checkpoint_every = cast(int, kwargs.get("triage_checkpoint_every", 50))
        self._triage_options = cast(
            TriageOptions, kwargs.get("triage_options") or TriageOptions()
        )
        memory_config = dict(kwargs.get("memory_config") or kwargs.get("memory") or {})
        execution_config_value = kwargs.get("execution_config")
        execution_config = ExecutionConfiguration.model_validate(
            load_execution_config()
            if execution_config_value is None
            else execution_config_value
        )
        codegraph_config = CodeGraphConfiguration.model_validate(
            kwargs.get("codegraph_config") or {}
        )
        reachability_config = ReachabilityConfiguration.model_validate(
            kwargs.get("reachability_config") or {}
        )
        reachability_settings = reachability_config.as_review_settings()
        reachability_settings["max_workers"] = max_workers
        reasoning_effort = chat_model_kwargs.get("reasoning_effort")
        if reasoning_effort is not None:
            reachability_settings["reasoning_effort"] = reasoning_effort

        plugin_config = dict(kwargs.get("plugin_config") or load_plugin_config())
        custom_guidance_precedence = plugin_config.get("general_prompts", {}).get(
            "custom_guidance_precedence", ""
        )
        language_registry = LanguagePluginRegistry.from_config(plugin_config)

        self._config = EngineConfig(
            codebase_path=self.codebase_path,
            vector_backend=vector_backend,
            llm_provider=llm_provider,
            embedding_provider=embedding_provider,
            usage_runtime=usage_runtime,
            plugin_config=plugin_config,
            custom_prompt_text=kwargs.get("custom_prompt_text"),
            custom_guidance_precedence=custom_guidance_precedence,
            max_workers=max_workers,
            max_token_length=max_token_length,
            llama_query_model=llama_query_model,
            chat_model_kwargs=chat_model_kwargs,
            similarity_top_k=similarity_top_k,
            doc_chunk_size=kwargs.get("doc_chunk_size", 1024),
            doc_chunk_overlap=kwargs.get("doc_chunk_overlap", 200),
            metisignore_file=kwargs.get("metisignore_file") or ".metisignore",
            review_code_include_paths=list(kwargs.get("review_code_include_paths", [])),
            review_code_exclude_paths=list(kwargs.get("review_code_exclude_paths", [])),
            capability_settings=capability_settings,
            memory_config=memory_config,
            threat_model_config=dict(kwargs.get("threat_model_config") or {}),
            language_registry=language_registry,
            code_exts=set(language_registry.supported_code_extensions()),
        )
        self._state = EngineState()
        self.repository = EngineRepository(self._config, self._state)
        selected_capabilities = execution_config.selected_capabilities()
        capability_configurations = dict(capability_settings.configurations)
        capability_configurations["memory"] = memory_config
        self.capabilities = build_engine_capabilities(
            selected_capabilities,
            capability_configurations,
            CapabilityCatalog(
                builtin_capability_registrations(
                    self._config,
                    self._state,
                    self.repository,
                )
            ),
            CapabilityContext(
                codebase_path=Path(self.codebase_path).expanduser().resolve(),
                repository=self.repository,
                max_workers=max_workers,
                max_token_length=max_token_length,
            ),
        )
        self._config.memory_service = None
        codegraphs = CodeGraphService(
            self._config,
            self.repository,
            discover_provider_factories(
                {
                    "c": CFamilyCodeGraphProvider,
                    "cpp": CFamilyCodeGraphProvider,
                },
            ),
            annotation_settings=codegraph_config,
            semantics=CodeGraphSemanticsCatalog(
                providers={
                    "c": CFamilyCodeGraphSemantics(),
                    "cpp": CFamilyCodeGraphSemantics(),
                },
            ),
        )
        try:
            builtin_execution = build_builtin_execution(
                execution_config,
                engine_config=self._config,
                repository=self.repository,
                capabilities=self.capabilities,
                codegraphs=codegraphs,
                triage_options=self._triage_options,
                triage_checkpoint_every=triage_checkpoint_every,
                reachability_settings=reachability_settings,
                review_graph_factory=self._get_review_graph,
            )
        except Exception:
            self.capabilities.close()
            raise
        self.execution = builtin_execution.execution
        self._triage_service = builtin_execution.triage_service
        self._simple_llm_triage = builtin_execution.simple_llm_triage
        self._config.memory_service = self.capabilities.get("memory")

    def init_codebase(self) -> dict[str, object]:
        with (
            bind_runlog(self._runlog),
            runlog.span("execution", "initialize") as execution_span,
        ):
            result = self.execution.execute_initialize()
            initialization = _require_execution_outputs(result)["initialize"]
            execution_span.end(
                status=result.status.value,
                attributes={
                    "outputs": initialization,
                    "diagnostics": result.diagnostics,
                },
            )
            return _execution_value(initialization)

    def execute_review(
        self,
        mode: Literal["code", "dir", "file", "patch"],
        *,
        target: str | None = None,
        callbacks: dict[str, object] | None = None,
    ) -> dict[str, object]:
        with (
            bind_runlog(self._runlog),
            runlog.span(
                "execution",
                "review",
                {"mode": mode, "target": target},
            ) as execution_span,
        ):
            result = self.execution.execute_review(
                ReviewCommand(mode=mode, target=target),
                callbacks=callbacks,
            )
            review = _require_execution_outputs(result)["review"]
            execution_span.end(
                status=result.status.value,
                attributes={"outputs": review, "diagnostics": result.diagnostics},
            )
            return _execution_value(review)

    def execute_graph(
        self,
        *,
        include_triaged: bool | None = None,
        callbacks: dict[str, object] | None = None,
    ) -> ExecutionResult:
        with (
            bind_runlog(self._runlog),
            runlog.span(
                "execution",
                "configured_graph",
                {"include_triaged": include_triaged},
            ) as execution_span,
        ):
            result = self.execution.execute_graph(
                include_triaged=include_triaged,
                callbacks=callbacks,
            )
            outputs = _require_execution_outputs(result)
            execution_span.end(
                status=result.status.value,
                attributes={"outputs": outputs, "diagnostics": result.diagnostics},
            )
            return ExecutionResult(
                status=result.status,
                outputs={
                    name: _execution_value(value) for name, value in outputs.items()
                },
                diagnostics=result.diagnostics,
            )

    def usage_command(
        self,
        command_name: str,
        target: str | None = None,
        display_name: str | None = None,
    ):
        return self._config.usage_runtime.command(
            command_name,
            target=target,
            display_name=display_name,
        )

    def finalize_usage_command(self, command) -> dict:
        return self._config.usage_runtime.finalize_command(command)

    def usage_totals(self) -> dict:
        return self._config.usage_runtime.snapshot_total()

    def has_usage(self) -> bool:
        return self._config.usage_runtime.has_usage()

    def save_usage_summary(self, output_path: str | None = None) -> str:
        return self._config.usage_runtime.save_run_summary(output_path)

    @property
    def indexing(self) -> IndexingService:
        return self._index_capability().indexing

    def _index_capability(self) -> IndexCapability:
        return cast(IndexCapability, self.capabilities.require("index"))

    def _get_review_graph(self, index: IndexCapability | None = None):
        cache_key = index is not None
        if cache_key not in self._state.review_graphs:
            model_tools = (
                index_model_tools(
                    index,
                    self.capabilities.manifest("index"),
                    max_contract_chars=(
                        self._config.capability_settings.model_tools.max_contract_chars
                    ),
                )
                if index is not None
                else ()
            )
            self._state.review_graphs[cache_key] = ReviewGraph(
                llm_provider=self._config.llm_provider,
                plugin_config=self._config.plugin_config,
                custom_prompt_text=self._config.custom_prompt_text,
                custom_guidance_precedence=self._config.custom_guidance_precedence,
                llama_query_model=self._config.llama_query_model,
                max_token_length=self._config.max_token_length,
                chat_model_kwargs=self._chat_model_kwargs(),
                model_tools=model_tools,
                model_tool_max_rounds=(
                    self._config.capability_settings.model_tools.max_rounds
                    if model_tools
                    else None
                ),
            )
        return self._state.review_graphs[cache_key]

    def _chat_model_kwargs(self) -> dict:
        return merge_chat_model_kwargs(
            self._config.chat_model_kwargs,
            self._config.usage_runtime.hooks.chat_model_kwargs(),
        )

    def _get_ask_graph(self):
        if self._state.ask_graph is None:
            self._state.ask_graph = AskGraph(
                llm_provider=self._config.llm_provider,
                llama_query_model=self._config.llama_query_model,
            )
        return self._state.ask_graph

    def ask_question(self, question):
        with (
            bind_runlog(self._runlog),
            runlog.span("execution", "ask", {"question": question}) as execution_span,
        ):
            retriever_code, retriever_docs = self._index_capability().get_retrievers()
            logger.info("Querying codebase for your question...")
            req = {
                "question": question,
                "retriever_code": retriever_code,
                "retriever_docs": retriever_docs,
            }
            result = self._get_ask_graph().ask(req)
            execution_span.end(attributes={"outputs": result})
            return result

    def execute_triage(
        self,
        payload: dict,
        codegraph: CodeGraphReference | None = None,
        progress_callback=None,
        debug_callback=None,
        checkpoint_callback=None,
        checkpoint_path: str | None = None,
        options: TriageOptions | None = None,
    ) -> dict:
        with (
            bind_runlog(self._runlog),
            runlog.span(
                "execution",
                "triage",
                {"include_triaged": bool(options and options.include_triaged)},
            ) as execution_span,
        ):
            options = options or self._triage_options
            if checkpoint_callback is None and checkpoint_path is not None:
                if self._triage_service is None:
                    raise RuntimeError("Triage stage is not configured")
                checkpoint_callback = self._triage_service.checkpoint_callback(
                    checkpoint_path
                )
            result = self.execution.execute_triage(
                payload,
                codegraph=codegraph,
                include_triaged=options.include_triaged,
                callbacks={
                    "progress_callback": progress_callback,
                    "debug_callback": debug_callback,
                    "checkpoint_callback": checkpoint_callback,
                },
            )
            triage = _require_execution_outputs(result)["triage"]
            execution_span.end(
                status=result.status.value,
                attributes={"outputs": triage, "diagnostics": result.diagnostics},
            )
            return _execution_value(triage)

    def close(self):
        if self._simple_llm_triage is not None:
            self._simple_llm_triage.close()
        self.capabilities.close()


def _execution_value(value):
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json", by_alias=True)
    if isinstance(value, dict):
        return {key: _execution_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_execution_value(item) for item in value]
    return value


def _require_execution_outputs(result):
    if result.status in {ExecutionStatus.OK, ExecutionStatus.INCONCLUSIVE}:
        for diagnostic in result.diagnostics:
            log = logger.warning if diagnostic.severity == "warning" else logger.error
            log(diagnostic.message)
        return result.outputs
    details = "; ".join(diagnostic.message for diagnostic in result.diagnostics)
    message = details or result.status.value
    raise RuntimeError(f"Execution graph failed: {message}")
