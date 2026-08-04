# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
from threading import Lock
from typing import Any
from typing import cast
from typing import TYPE_CHECKING

from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import CapabilityRequirement
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.codegraph import CodeGraphReference
from metis.engine.stages.triage.models import TriageRun

if TYPE_CHECKING:
    from .service import ReachabilityTriageService
    from metis.engine.nodes.simple_llm_triage.service import SimpleLlmTriageService
    from metis.engine.capabilities.navigation import NavigationCapability
    from metis.memory import MemoryService

logger = logging.getLogger("metis")


def create_node(
    reachability: ReachabilityTriageService,
    simple_llm: SimpleLlmTriageService,
) -> NodeRegistration:
    def execute(invocation: NodeInvocation) -> NodeResult:
        request = cast(TriageRun, invocation.inputs["request"])
        codegraph = cast(
            CodeGraphReference | None,
            invocation.inputs["codegraph"],
        )
        graph = (
            invocation.context.codegraphs.load(codegraph)
            if codegraph is not None
            else None
        )
        adjudicator = invocation.context.triage
        if adjudicator is None:
            raise RuntimeError("Triage adjudication is unavailable")
        memory = cast(
            "MemoryService | None", invocation.context.capabilities.get("memory")
        )
        navigation = cast(
            "NavigationCapability",
            invocation.context.capabilities["navigation"],
        )
        primary = (
            reachability.classifier(
                graph,
                unavailable_files=codegraph.failed_files,
                navigation=navigation,
                model_tool_max_rounds=(
                    invocation.context.runtime.model_tool_max_rounds
                ),
            )
            if graph is not None and codegraph is not None
            else None
        )
        warned_paths: set[str] = set()
        warning_lock = Lock()

        def classify(
            finding: Any,
            threat_model_context: list[dict[str, Any]],
            debug_callback: object,
        ) -> dict[str, Any] | None:
            decision = (
                primary(finding, threat_model_context, debug_callback)
                if primary is not None
                else None
            )
            if decision is not None:
                return decision
            path = str(finding.file_path or "<unknown>")
            with warning_lock:
                should_warn = path not in warned_paths
                warned_paths.add(path)
            if should_warn:
                logger.warning(
                    "Reachability triage is unavailable for %s; "
                    "using simple LLM triage",
                    path,
                )
            return simple_llm.classify(
                finding,
                threat_model_context,
                debug_callback,
                navigation=navigation,
                model_tool_max_rounds=(
                    invocation.context.runtime.model_tool_max_rounds
                ),
            )

        triaged = adjudicator.triage_run(
            request,
            classifier=classify,
            memory_service=memory,
            progress_callback=invocation.context.callbacks.progress,
            debug_callback=invocation.context.callbacks.debug,
            checkpoint_callback=invocation.context.callbacks.checkpoint,
        )
        return NodeResult({"run": triaged})

    return NodeRegistration(
        name="reachability_triage",
        stage="triage",
        configuration=EmptyNodeConfiguration,
        inputs={
            "request": TriageRun,
            "codegraph": CodeGraphReference | None,
        },
        outputs={"run": TriageRun},
        execute=execute,
        capabilities={
            "memory": CapabilityRequirement.OPTIONAL,
            "navigation": CapabilityRequirement.REQUIRED,
        },
    )
