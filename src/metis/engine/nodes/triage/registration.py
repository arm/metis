# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from functools import partial
from typing import cast
from typing import TYPE_CHECKING

from metis.engine.codegraph import CodeGraphReference
from metis.engine.codegraph import FunctionNode
from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import CapabilityRequirement
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.nodes.reachability.graph_utils import _build_reverse_edges
from metis.engine.stages.triage.models import TriageRun

if TYPE_CHECKING:
    from .service import TriageClassifierService
    from metis.engine.capabilities.navigation import NavigationCapability
    from metis.memory import MemoryService


def create_node(
    classifier_service: TriageClassifierService,
) -> NodeRegistration:
    def execute(invocation: NodeInvocation) -> NodeResult:
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
        reference = cast(CodeGraphReference | None, invocation.inputs["codegraph"])
        codegraph = (
            invocation.context.codegraphs.load(reference)
            if reference is not None
            else None
        )
        run = cast(TriageRun, invocation.inputs["request"])
        codegraph_file_nodes: dict[str, list[FunctionNode]] | None = None
        codegraph_callers: dict[str, tuple[str, ...]] | None = None
        if codegraph is not None and run.remaining:
            codegraph_file_nodes = {}
            for node in codegraph.nodes.values():
                codegraph_file_nodes.setdefault(node.file_path, []).append(node)
            codegraph_callers = {
                name: tuple(dict.fromkeys(callers))
                for name, callers in _build_reverse_edges(codegraph, str).items()
            }
        triaged = adjudicator.triage_run(
            run,
            jobs=invocation.context.jobs,
            classifier=partial(
                classifier_service.classify,
                navigation=navigation,
                codegraph=codegraph,
                unavailable_files=(
                    reference.failed_files if reference is not None else ()
                ),
                model=invocation.context.runtime.model,
                model_tool_max_rounds=(
                    invocation.context.runtime.model_tool_max_rounds
                ),
                codegraph_file_nodes=codegraph_file_nodes,
                codegraph_callers=codegraph_callers,
            ),
            memory_service=memory,
            progress_callback=invocation.context.callbacks.progress,
            debug_callback=invocation.context.callbacks.debug,
            checkpoint_callback=invocation.context.callbacks.checkpoint,
        )
        return NodeResult({"run": triaged})

    return NodeRegistration(
        name="triage",
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
