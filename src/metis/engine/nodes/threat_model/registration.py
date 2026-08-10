# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Literal
from typing import cast
from typing import TYPE_CHECKING

from pydantic import BaseModel
from pydantic import ConfigDict

from .service import initialize_threat_model_memory

from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import CapabilityRequirement
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis import runlog


if TYPE_CHECKING:
    from metis.engine.repository import EngineRepository
    from metis.engine.runtime import EngineConfig
    from metis.memory import MemoryService


class InitializedThreatModelResult(BaseModel):
    status: Literal["ok"]
    records_written: int
    records_deleted: int
    authoritative_sources: list[str]

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def create_node(
    engine_config: EngineConfig,
    repository: EngineRepository,
) -> NodeRegistration:
    def execute(invocation: NodeInvocation) -> NodeResult:
        memory_service = cast(
            "MemoryService", invocation.context.capabilities["memory"]
        )
        result = InitializedThreatModelResult.model_validate(
            initialize_threat_model_memory(
                engine_config,
                repository,
                memory_service,
            )
        )
        runlog.event(
            "artifact",
            {"kind": "threat_model_snapshot", "payload": result},
        )
        return NodeResult({"threat_model": result})

    return NodeRegistration(
        name="threat_model",
        stage="initialize",
        configuration=EmptyNodeConfiguration,
        inputs={},
        outputs={"threat_model": InitializedThreatModelResult},
        execute=execute,
        capabilities={"memory": CapabilityRequirement.REQUIRED},
    )
