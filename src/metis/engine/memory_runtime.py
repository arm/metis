# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

from metis.engine.capabilities.contracts import CapabilityContext
from metis.memory import MemoryService
from metis.memory.configuration import MemoryCapabilityConfiguration
from metis.memory.registry import build_memory_store
from metis.utils import resolve_path_within_root


def create_memory_service(
    context: CapabilityContext,
    configuration: MemoryCapabilityConfiguration,
) -> MemoryService:
    backend = configuration.backend.strip().lower()
    root = context.codebase_path
    return MemoryService(
        build_memory_store(_memory_path(root, configuration.location), backend=backend),
        repo_root=str(root),
    )


def _memory_path(root: Path, configured_path: str) -> Path:
    path = Path(configured_path)
    try:
        return resolve_path_within_root(root, path)
    except ValueError as exc:
        raise ValueError(
            "Repository memory path must stay under codebase_path"
        ) from exc
