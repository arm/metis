# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy

from langchain_core.tools import StructuredTool

from metis.engine.capabilities.catalog import get_capability_contract
from metis.engine.capabilities.manifest import CapabilityManifest
from metis.engine.capabilities.navigation import NavigationCapability


def navigation_model_tools(
    capability: NavigationCapability,
    manifest: CapabilityManifest,
    *,
    max_contract_chars: int,
) -> tuple[StructuredTool, ...]:
    metadata = _model_tool_metadata(manifest, max_contract_chars)
    tools = []
    for operation in _model_tool_operations(manifest):
        func = getattr(capability, operation.operation or operation.name)
        tools.append(
            StructuredTool.from_function(
                func=func,
                name=operation.name,
                description=operation.description,
                args_schema=deepcopy(operation.input_schema) or None,
                metadata=metadata,
            )
        )
    return tuple(tools)


def _model_tool_operations(manifest: CapabilityManifest):
    if not manifest.active:
        return ()
    return tuple(
        operation
        for operation in manifest.operations
        if operation.status == "active" and "model_tool" in operation.surfaces
    )


def _model_tool_metadata(
    manifest: CapabilityManifest, max_contract_chars: int
) -> dict[str, object] | None:
    contract = get_capability_contract(manifest)
    if not contract:
        return None
    return {
        "metis_contract": contract,
        "metis_contract_max_chars": max_contract_chars,
    }
