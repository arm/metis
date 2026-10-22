# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from langchain_core.tools import StructuredTool

from metis.engine.capabilities.index import IndexCapability
from metis.engine.capabilities.manifest import CapabilityManifest

from .manifest import manifest_model_tools
from .manifest import model_tool_enabled


def index_model_tools(
    capability: IndexCapability,
    manifest: CapabilityManifest,
    *,
    max_contract_chars: int,
) -> tuple[StructuredTool, ...]:
    operation = _index_search_operation(manifest)
    if operation is None or not capability.supports_search():
        return ()
    return manifest_model_tools(
        manifest,
        (operation,),
        lambda operation: capability.search,
        max_contract_chars=max_contract_chars,
    )


def _index_search_operation(manifest: CapabilityManifest):
    if not manifest.active:
        return None
    for operation in manifest.operations:
        if operation.id == "index.search":
            if model_tool_enabled(operation):
                return operation
            return None
    return None
