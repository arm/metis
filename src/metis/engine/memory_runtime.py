# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

from metis.memory import MemoryService
from metis.memory.registry import build_memory_store
from metis.utils import resolve_path_within_root

from .runtime import EngineConfig


def create_memory_service(config: EngineConfig) -> MemoryService | None:
    if not config.memory_config.get("enabled", False):
        return None
    backend = str(config.memory_config.get("backend") or "sqlite").strip().lower()
    return MemoryService(
        build_memory_store(_memory_path(config), backend=backend),
        repo_root=str(_codebase_root(config)),
    )


def _memory_path(config: EngineConfig) -> Path:
    path = Path(
        str(
            config.memory_config.get("location") or ".metis/memory/metis_memory.sqlite3"
        )
    )
    root = _codebase_root(config)
    try:
        return resolve_path_within_root(root, path)
    except ValueError as exc:
        raise ValueError(
            "Repository memory path must stay under codebase_path"
        ) from exc


def _codebase_root(config: EngineConfig) -> Path:
    return Path(config.codebase_path).expanduser().resolve()
