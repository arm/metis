# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import threading

from metis.engine.graphs import TriageGraph
from metis.engine.reachability.options import ReachabilityReviewOptions
from metis.engine.reachability.triage import ReachabilityTriageRequest
from metis.engine.tools.registry import build_toolbox
from metis.chat_model_options import merge_chat_model_kwargs

logger = logging.getLogger("metis")


class TriageServiceRuntimeMixin:
    def _build_triage_graph(self):
        toolbox = build_toolbox(
            policy="triage_evidence",
            codebase_path=self.codebase_path,
            timeout_seconds=self.triage_tool_timeout_seconds,
        )
        usage_chat_kwargs = (
            self._usage_hooks.chat_model_kwargs() if self._usage_hooks else None
        )
        return TriageGraph(
            llm_provider=self.llm_provider,
            llama_query_model=self.llama_query_model,
            toolbox=toolbox,
            plugin_config=self.plugin_config,
            chat_model_kwargs=merge_chat_model_kwargs(
                self.chat_model_kwargs,
                usage_chat_kwargs,
            ),
            model_tools=self.model_tools,
            model_tool_max_rounds=self.model_tool_max_rounds,
        )

    def _get_thread_triage_graph(self):
        graph = getattr(self._triage_graph_local, "graph", None)
        if graph is None:
            graph = self._build_triage_graph()
            self._triage_graph_local.graph = graph
        return graph

    def _get_triage_plugin(self, file_path: str):
        if not file_path:
            return None
        return self._get_plugin_for_path(file_path)

    def _get_triage_language_guidance(self, plugin) -> str:
        if plugin is None:
            return ""
        get_prompts = getattr(plugin, "get_prompts", None)
        if not callable(get_prompts):
            return ""
        try:
            prompts = get_prompts()
        except Exception as exc:
            logger.warning("Failed to load triage language guidance: %s", exc)
            return ""
        if not isinstance(prompts, dict):
            return ""
        return str(prompts.get("triage_navigation") or "").strip()

    def _supports_reachability_triage(self, file_path: str) -> bool:
        supports_file = getattr(self.reachability_service, "supports_file", None)
        if not callable(supports_file):
            return False
        return bool(supports_file(file_path))

    def _reachability_triage_options(self):
        return ReachabilityReviewOptions.from_kwargs(
            self.reachability_settings,
            default_workers=self.max_workers,
        )

    def _reachability_triage_request(self, finding) -> ReachabilityTriageRequest:
        return ReachabilityTriageRequest(
            message=finding.message,
            file_path=finding.file_path,
            line=finding.line,
            rule_id=finding.rule_id,
            snippet=finding.snippet,
            source_tool=getattr(finding, "source_tool", ""),
            explanation=getattr(finding, "explanation", ""),
        )

    def close(self):
        self._triage_graph_local = threading.local()
