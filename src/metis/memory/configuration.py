# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

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
    def normalize_store(cls, value: object) -> dict[str, str]:
        configured = value if isinstance(value, dict) else {}
        spec = parse_memory_store_spec(
            str(configured.get("location") or cls.model_fields["location"].default),
            backend=str(
                configured.get("backend") or cls.model_fields["backend"].default
            ),
        )
        return {"backend": spec.backend, "location": spec.location}
