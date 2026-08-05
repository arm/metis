# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy

from langchain_core.tools import StructuredTool

from metis.engine.capabilities.catalog import get_capability_contract
from metis.engine.capabilities.index import IndexCapability
from metis.engine.capabilities.manifest import CapabilityManifest


def index_model_tools(
    capability: IndexCapability,
    manifest: CapabilityManifest,
    *,
    max_contract_chars: int,
) -> tuple[StructuredTool, ...]:
    operation = _index_search_operation(manifest)
    if operation is None or not capability.supports_search():
        return ()
    contract = get_capability_contract(manifest)
    metadata: dict[str, object] | None = None
    if contract:
        metadata = {
            "metis_contract": contract,
            "metis_contract_max_chars": max_contract_chars,
        }
    return (
        StructuredTool.from_function(
            func=capability.search,
            name=operation.name,
            description=operation.description,
            args_schema=deepcopy(operation.input_schema) or None,
            metadata=metadata,
        ),
    )


def _index_search_operation(manifest: CapabilityManifest):
    if not manifest.active:
        return None
    for operation in manifest.operations:
        if operation.id == "index.search":
            if operation.status == "active" and "model_tool" in operation.surfaces:
                return operation
            return None
    return None
