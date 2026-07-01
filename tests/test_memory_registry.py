# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from metis.memory import SQLiteMemoryStore
from metis.memory.registry import build_memory_store
from metis.memory.registry import MemoryStoreSpec
from metis.memory.registry import parse_memory_store_spec
from metis.memory.registry import register_memory_store_backend


def test_memory_store_factory_uses_explicit_backend(tmp_path):
    path = tmp_path / "memory.sqlite3"

    spec = parse_memory_store_spec(path, backend="sqlite")
    store = build_memory_store(path, backend="sqlite")

    assert spec.backend == "sqlite"
    assert spec.location == str(path)
    assert isinstance(store, SQLiteMemoryStore)
    assert store.path == path


def test_memory_store_factory_uses_registered_backend():
    captured: list[MemoryStoreSpec] = []
    expected_store = object()

    def _factory(spec: MemoryStoreSpec):
        captured.append(spec)
        return expected_store

    register_memory_store_backend("unit-test-backend", _factory)

    store = build_memory_store("unit-test-location", backend="unit-test-backend")

    assert store is expected_store
    assert captured == [
        MemoryStoreSpec(backend="unit-test-backend", location="unit-test-location")
    ]
