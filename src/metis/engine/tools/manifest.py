# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Callable
from collections.abc import Iterable
from copy import deepcopy
from typing import Any

from langchain_core.tools import StructuredTool

from metis.engine.capabilities.catalog import get_capability_contract
from metis.engine.capabilities.manifest import CapabilityManifest
from metis.engine.capabilities.manifest import CapabilityOperationManifest


def model_tool_enabled(operation: CapabilityOperationManifest) -> bool:
    return operation.status == "active" and "model_tool" in operation.surfaces


def manifest_model_tools(
    manifest: CapabilityManifest,
    operations: Iterable[CapabilityOperationManifest],
    bind: Callable[[CapabilityOperationManifest], Callable[..., Any]],
    *,
    max_contract_chars: int,
) -> tuple[StructuredTool, ...]:
    contract = get_capability_contract(manifest)
    metadata = (
        {"metis_contract": contract, "metis_contract_max_chars": max_contract_chars}
        if contract
        else None
    )
    if not manifest.active:
        return ()
    return tuple(
        StructuredTool.from_function(
            func=bind(operation),
            name=operation.name,
            description=operation.description,
            args_schema=deepcopy(operation.input_schema) or None,
            metadata=metadata,
        )
        for operation in operations
        if model_tool_enabled(operation)
    )
