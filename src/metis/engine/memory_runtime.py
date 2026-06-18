# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

from metis.memory import MemoryService
from metis.memory import SQLiteMemoryStore

from .runtime import EngineConfig


def create_memory_service(config: EngineConfig) -> MemoryService | None:
    if not config.memory_config.get("enabled", False):
        return None
    backend = str(config.memory_config.get("backend") or "sqlite").strip().lower()
    if backend in {"none", "disabled"}:
        return None
    if backend != "sqlite":
        raise ValueError(f"Unsupported memory backend: {backend}")
    return MemoryService(
        SQLiteMemoryStore(_memory_path(config)),
        repo_root=str(_codebase_root(config)),
    )


def _memory_path(config: EngineConfig) -> Path:
    raw_path = config.memory_config.get("location") or config.memory_config.get("path")
    path = Path(str(raw_path or ".metis/memory/metis_memory.sqlite3"))
    if path.is_absolute():
        return path
    return _codebase_root(config) / path


def _codebase_root(config: EngineConfig) -> Path:
    root = Path(str(config.codebase_path or ".")).expanduser()
    if not root.is_absolute():
        root = Path.cwd() / root
    return root.resolve()
