# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest
from pydantic import ValidationError

from metis.configuration import load_runtime_config
from metis.memory import SQLiteMemoryStore
from metis.memory.configuration import MemoryCapabilityConfiguration
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


def test_memory_configuration_preserves_defaults_and_normalization(tmp_path):
    defaults = MemoryCapabilityConfiguration()
    for value in (None, {"backend": None, "location": ""}):
        assert MemoryCapabilityConfiguration.model_validate(value) == defaults
    value = {"backend": " SQLite ", "location": tmp_path / "memory.sqlite3"}
    configuration = MemoryCapabilityConfiguration.model_validate(value)
    assert configuration.backend == "sqlite"
    assert configuration.location == str(value["location"])


@pytest.mark.parametrize(
    "value", ["{locaton: custom.sqlite3}", "{backend: 123}", "{location: false}", "[]"]
)
def test_runtime_configuration_rejects_invalid_memory_values(tmp_path, value):
    path = tmp_path / "metis.yaml"
    path.write_text(
        f"memory: {value}\nllm_provider:\n  name: openai\n  model: gpt-test\n"
        "  api_key: test-key\n"
    )
    with pytest.raises(ValidationError):
        load_runtime_config(path)
