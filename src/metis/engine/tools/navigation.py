# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from langchain_core.tools import StructuredTool

from metis.engine.capabilities.manifest import CapabilityManifest
from metis.engine.capabilities.navigation import NavigationCapability

from .manifest import manifest_model_tools


def navigation_model_tools(
    capability: NavigationCapability,
    manifest: CapabilityManifest,
    *,
    max_contract_chars: int,
) -> tuple[StructuredTool, ...]:
    return manifest_model_tools(
        manifest,
        manifest.operations,
        lambda operation: getattr(capability, operation.operation or operation.name),
        max_contract_chars=max_contract_chars,
    )
