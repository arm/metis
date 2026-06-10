# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import threading

from metis.engine.analysis.base import AnalyzerEvidence, AnalyzerRequest
from metis.engine.graphs import TriageGraph
from metis.engine.tools.registry import build_toolbox
from metis.exceptions import RetrieverInitError

from .triage_constants import DEFAULT_TRIAGE_SIMILARITY_TOP_K

logger = logging.getLogger("metis")


class _FallbackTriageAnalyzer:
    def supports_file(self, rel_path: str) -> bool:
        return bool(rel_path)

    def collect_evidence(self, request: AnalyzerRequest) -> AnalyzerEvidence:
        unresolved = []
        if request.file_path:
            unresolved.append(
                f"SYMBOL_DEFINITION_UNRESOLVED:{request.file_path}:{request.line}"
            )
        return AnalyzerEvidence(
            supported=False,
            language="fallback",
            summary=(
                "No language-specific triage analyzer is available for this finding. "
                "Falling back to grep/sed based evidence collection."
            ),
            unresolved_hops=unresolved,
        )


class TriageServiceRuntimeMixin:
    def _build_triage_graph(self):
        toolbox = build_toolbox(
            policy="triage_evidence",
            codebase_path=self.codebase_path,
            timeout_seconds=self.triage_tool_timeout_seconds,
        )
        return TriageGraph(
            llm_provider=self.llm_provider,
            llama_query_model=self.llama_query_model,
            toolbox=toolbox,
            plugin_config=self.plugin_config,
            chat_model_kwargs=(
                self._usage_hooks.chat_model_kwargs() if self._usage_hooks else {}
            ),
        )

    def _get_thread_triage_graph(self):
        graph = getattr(self._triage_graph_local, "graph", None)
        if graph is None:
            graph = self._build_triage_graph()
            self._triage_graph_local.graph = graph
        return graph

    def _init_and_get_triage_retrievers(self):
        top_k = self._normalize_top_k(
            self.triage_similarity_top_k, DEFAULT_TRIAGE_SIMILARITY_TOP_K
        )
        retriever_code, retriever_docs = self._create_retrievers(top_k)
        if not retriever_code or not retriever_docs:
            raise RetrieverInitError()
        return retriever_code, retriever_docs

    def _get_thread_triage_retrievers(self):
        retrievers = getattr(self._triage_retrievers_local, "retrievers", None)
        if retrievers is None:
            retrievers = self._init_and_get_triage_retrievers()
            self._triage_retrievers_local.retrievers = retrievers
        return retrievers

    def _get_triage_plugin(self, file_path: str):
        if not file_path:
            return None
        return self._get_plugin_for_path(file_path)

    def _build_triage_analyzer_from_plugin(self, plugin, language_name: str):
        method = getattr(plugin, "get_triage_analyzer_factory", None)
        if not callable(method):
            return _FallbackTriageAnalyzer()
        try:
            factory = method()
        except Exception as exc:
            logger.warning(
                "Failed to obtain triage analyzer factory for language '%s': %s",
                language_name,
                exc,
            )
            return _FallbackTriageAnalyzer()
        if not callable(factory):
            return _FallbackTriageAnalyzer()
        try:
            return factory(self.codebase_path)
        except Exception as exc:
            logger.warning(
                "Failed to build triage analyzer for language '%s': %s",
                language_name,
                exc,
            )
            return _FallbackTriageAnalyzer()

    def _get_thread_triage_analyzer(self, file_path: str):
        language_name = self._get_language_name_for_path(file_path or "")
        if not language_name:
            return _FallbackTriageAnalyzer()
        analyzers = getattr(self._triage_analyzers_local, "by_language", None)
        if analyzers is None:
            analyzers = {}
            self._triage_analyzers_local.by_language = analyzers
        if language_name not in analyzers:
            plugin = self._get_plugin_for_path(file_path)
            if plugin is None:
                analyzers[language_name] = _FallbackTriageAnalyzer()
            else:
                analyzers[language_name] = self._build_triage_analyzer_from_plugin(
                    plugin,
                    language_name,
                )
        return analyzers[language_name]

    def close(self):
        self._triage_graph_local = threading.local()
        self._triage_retrievers_local = threading.local()
        self._triage_analyzers_local = threading.local()
