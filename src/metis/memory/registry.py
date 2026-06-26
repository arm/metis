# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .base import StoreLike
from .sqlite_store import SQLiteMemoryStore


@dataclass(frozen=True)
class MemoryStoreSpec:
    backend: str
    location: str


MemoryStoreFactory = Callable[[MemoryStoreSpec], StoreLike]

_MEMORY_STORE_FACTORIES: dict[str, MemoryStoreFactory] = {}


def build_memory_store(
    location: str | Path,
    *,
    backend: str | None = None,
) -> StoreLike:
    spec = parse_memory_store_spec(location, backend=backend)
    factory = get_memory_store_backend(spec.backend)
    return factory(spec)


def parse_memory_store_spec(
    location: str | Path,
    *,
    backend: str | None = None,
) -> MemoryStoreSpec:
    raw = str(location)
    backend_name = _normalize_backend_name(backend or "sqlite")
    return MemoryStoreSpec(
        backend=backend_name,
        location=raw,
    )


def register_memory_store_backend(
    name: str,
    factory: MemoryStoreFactory,
) -> None:
    _MEMORY_STORE_FACTORIES[_normalize_backend_name(name)] = factory


def get_memory_store_backend(name: str) -> MemoryStoreFactory:
    key = _normalize_backend_name(name)
    if key in _MEMORY_STORE_FACTORIES:
        return _MEMORY_STORE_FACTORIES[key]
    raise ValueError(f"Unsupported memory store backend: {name}")


def _normalize_backend_name(name: str) -> str:
    normalized = name.strip().lower()
    if not normalized:
        raise ValueError("Memory store backend name must not be empty.")
    return normalized


def _build_sqlite_memory_store(spec: MemoryStoreSpec) -> SQLiteMemoryStore:
    return SQLiteMemoryStore(Path(spec.location).expanduser())


register_memory_store_backend("sqlite", _build_sqlite_memory_store)
