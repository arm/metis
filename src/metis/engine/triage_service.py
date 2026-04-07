# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import threading
from typing import Any, Callable

from metis.usage import UsageHooks

from .triage_service_exec import TriageServiceExecutionMixin
from .triage_service_exec import save_sarif_file
from .triage_service_runtime import TriageServiceRuntimeMixin

__all__ = ["TriageService", "save_sarif_file"]


class TriageService(TriageServiceRuntimeMixin, TriageServiceExecutionMixin):
    def __init__(
        self,
        *,
        codebase_path: str,
        llm_provider: Any,
        llama_query_model: str,
        plugin_config: dict[str, Any],
        max_workers: int,
        triage_similarity_top_k: int,
        triage_checkpoint_every: int,
        triage_tool_timeout_seconds: int,
        normalize_top_k: Callable[[Any, int], int],
        create_query_engines: Callable[[int], tuple[Any, Any]],
        get_plugin_for_extension: Callable[[str], Any],
        usage_hooks: UsageHooks | None = None,
    ):
        self.codebase_path = codebase_path
        self.llm_provider = llm_provider
        self.llama_query_model = llama_query_model
        self.plugin_config = plugin_config
        self.max_workers = max(1, max_workers)
        self.triage_similarity_top_k = triage_similarity_top_k
        self.triage_checkpoint_every = triage_checkpoint_every
        self.triage_tool_timeout_seconds = int(triage_tool_timeout_seconds)
        self._normalize_top_k = normalize_top_k
        self._create_query_engines = create_query_engines
        self._get_plugin_for_extension = get_plugin_for_extension
        self._usage_hooks = usage_hooks

        self._triage_graph_local = threading.local()
        self._triage_query_engines_local = threading.local()
        self._triage_analyzers_local = threading.local()
