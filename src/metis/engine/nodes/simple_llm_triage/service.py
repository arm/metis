# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any
from typing import TYPE_CHECKING

from metis.chat_model_options import merge_chat_model_kwargs
from metis.engine.stages.triage.models import TriageRequest
from metis.engine.tools.navigation import navigation_model_tools
from metis.usage import UsageHooks

from .workflow import TriageWorkflow

logger = logging.getLogger("metis")

if TYPE_CHECKING:
    from metis.engine.capabilities.manifest import CapabilityManifest
    from metis.engine.capabilities.navigation import NavigationCapability


class SimpleLlmTriageService:
    def __init__(
        self,
        *,
        llm_provider: Any,
        model: str,
        chat_model_kwargs: dict[str, Any],
        plugin_config: dict[str, Any],
        get_plugin_for_path: Callable[[str], Any],
        get_language_name_for_path: Callable[[str], str | None],
        usage_hooks: UsageHooks | None,
        model_tool_max_contract_chars: int,
        navigation_manifest: CapabilityManifest,
    ) -> None:
        self._llm_provider = llm_provider
        self._model = model
        self._chat_model_kwargs = dict(chat_model_kwargs)
        self._plugin_config = plugin_config
        self._get_plugin_for_path = get_plugin_for_path
        self._get_language_name_for_path = get_language_name_for_path
        self._usage_hooks = usage_hooks
        self._model_tool_max_contract_chars = model_tool_max_contract_chars
        self._navigation_manifest = navigation_manifest
        self._local = threading.local()

    def classify(
        self,
        finding: Any,
        threat_model_context: list[dict[str, Any]],
        debug_callback: object,
        *,
        navigation: NavigationCapability,
        model_tool_max_rounds: int | None = None,
    ) -> dict | None:
        request: TriageRequest = {
            "finding_message": finding.message,
            "finding_file_path": finding.file_path,
            "finding_line": finding.line,
            "finding_rule_id": finding.rule_id,
            "finding_snippet": finding.snippet,
            "finding_source_tool": getattr(finding, "source_tool", ""),
            "finding_is_metis": bool(getattr(finding, "is_metis_source", False)),
            "finding_explanation": getattr(finding, "explanation", ""),
            "debug_callback": debug_callback,
            "triage_language": self._get_language_name_for_path(finding.file_path or "")
            or "",
            "triage_language_guidance": self._language_guidance(finding.file_path),
            "threat_model_context": threat_model_context,
        }
        return self._workflow(navigation, model_tool_max_rounds).triage(request)

    def close(self) -> None:
        self._local = threading.local()

    def _workflow(
        self,
        navigation: NavigationCapability,
        model_tool_max_rounds: int | None,
    ) -> TriageWorkflow:
        workflow = getattr(self._local, "workflow", None)
        workflow_key = (id(navigation), model_tool_max_rounds)
        if (
            workflow is None
            or getattr(self._local, "workflow_key", None) != workflow_key
        ):
            usage_kwargs = (
                self._usage_hooks.chat_model_kwargs() if self._usage_hooks else None
            )
            model_tools = navigation_model_tools(
                navigation,
                self._navigation_manifest,
                max_contract_chars=self._model_tool_max_contract_chars,
            )
            workflow = TriageWorkflow(
                llm_provider=self._llm_provider,
                llama_query_model=self._model,
                toolbox=navigation,
                plugin_config=self._plugin_config,
                chat_model_kwargs=merge_chat_model_kwargs(
                    self._chat_model_kwargs,
                    usage_kwargs,
                ),
                model_tools=model_tools,
                model_tool_max_rounds=(model_tool_max_rounds if model_tools else None),
            )
            self._local.workflow = workflow
            self._local.workflow_key = workflow_key
        return workflow

    def _language_guidance(self, file_path: str) -> str:
        plugin = self._get_plugin_for_path(file_path) if file_path else None
        if plugin is None:
            return ""
        try:
            prompts = plugin.get_prompts()
        except Exception as exc:
            logger.warning("Failed to load triage language guidance: %s", exc)
            return ""
        if not isinstance(prompts, dict):
            return ""
        return str(prompts.get("triage_navigation") or "").strip()
