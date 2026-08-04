# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import cast
from typing import Literal
from typing import TYPE_CHECKING

from pydantic import BaseModel
from pydantic import ConfigDict

from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import CapabilityRequirement
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult

if TYPE_CHECKING:
    from metis.engine.capabilities.index import IndexCapability


class IndexInitializationResult(BaseModel):
    status: Literal["indexed"]

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def execute(invocation: NodeInvocation) -> NodeResult:
    index = cast("IndexCapability", invocation.context.capabilities["index"])
    index.indexing.index_codebase()
    return NodeResult({"index": IndexInitializationResult(status="indexed")})


registration = NodeRegistration(
    name="index",
    stage="initialize",
    configuration=EmptyNodeConfiguration,
    inputs={},
    outputs={"index": IndexInitializationResult},
    execute=execute,
    capabilities={"index": CapabilityRequirement.REQUIRED},
)
