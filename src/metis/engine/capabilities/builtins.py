# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import cast

from pydantic import BaseModel

from metis.engine.memory_runtime import create_memory_service
from metis.engine.repository import EngineRepository
from metis.engine.runtime import EngineConfig
from metis.engine.runtime import EngineState
from metis.memory import MemoryService
from metis.memory.configuration import MemoryCapabilityConfiguration

from .catalog import get_capability_manifest
from .contracts import CapabilityContext
from .contracts import CapabilityRegistration
from .index import IndexCapability
from .index import IndexCapabilityConfiguration
from .manifest import CapabilityManifest
from .navigation import NavigationCapability
from .navigation import NavigationCapabilityConfiguration


def builtin_capability_registrations(
    config: EngineConfig,
    state: EngineState,
    repository: EngineRepository,
) -> tuple[CapabilityRegistration, ...]:
    def build_index(
        _context: CapabilityContext, configuration: BaseModel
    ) -> IndexCapability:
        parsed = cast(IndexCapabilityConfiguration, configuration)
        return IndexCapability(config, state, repository, parsed.search)

    def build_navigation(
        context: CapabilityContext, configuration: BaseModel
    ) -> NavigationCapability:
        parsed = cast(NavigationCapabilityConfiguration, configuration)
        return NavigationCapability(
            codebase_path=str(context.codebase_path),
            timeout_seconds=parsed.timeout_seconds,
            max_chars=parsed.max_chars,
        )

    def build_memory(
        context: CapabilityContext, configuration: BaseModel
    ) -> MemoryService:
        return create_memory_service(
            context,
            cast(MemoryCapabilityConfiguration, configuration),
        )

    return (
        CapabilityRegistration(
            _required_manifest("index"),
            IndexCapabilityConfiguration,
            build_index,
            close=lambda capability: cast(IndexCapability, capability).close(),
        ),
        CapabilityRegistration(
            _required_manifest("navigation"),
            NavigationCapabilityConfiguration,
            build_navigation,
        ),
        CapabilityRegistration(
            _required_manifest("memory"),
            MemoryCapabilityConfiguration,
            build_memory,
        ),
    )


def _required_manifest(name: str) -> CapabilityManifest:
    manifest = get_capability_manifest(name)
    if manifest is None:
        raise RuntimeError(f"Built-in capability manifest {name!r} is missing")
    return manifest
