# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import model_validator

from .registry import parse_memory_store_spec


class MemoryCapabilityConfiguration(BaseModel):
    backend: str = "sqlite"
    location: str = ".metis/memory/metis_memory.sqlite3"

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def normalize_store(cls, value: object) -> object:
        if value is None:
            return {}
        if not isinstance(value, dict):
            return value
        configured = value.copy()
        for name in ("backend", "location"):
            if configured.get(name) is None or configured[name] == "":
                configured[name] = cls.model_fields[name].default
        if isinstance(configured["backend"], str) and isinstance(
            configured["location"], (str, Path)
        ):
            spec = parse_memory_store_spec(
                configured["location"], backend=configured["backend"]
            )
            configured.update(backend=spec.backend, location=spec.location)
        return configured
