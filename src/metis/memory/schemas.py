# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from dataclasses import fields
from datetime import datetime
from datetime import timezone
from typing import Any

from .base import Namespace

_STORE_METADATA_FIELDS = frozenset({"namespace", "key", "created_at"})


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class MemoryRecord:
    namespace: Namespace
    key: str
    artifact_type: str
    schema_version: int
    tool_version: str
    repo_fingerprint: str
    input_fingerprint: str
    created_at: str
    memory_type: str
    authority: str = ""
    source_kind: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    body_json: dict[str, Any] | list[Any] | None = None
    body_markdown: str = ""
    summary_text: str = ""
    search_text: str = ""

    @classmethod
    def create(
        cls,
        *,
        namespace: Namespace,
        key: str,
        tool_version: str,
        **value: Any,
    ) -> "MemoryRecord":
        record_value = dict(value)
        record_value["tool_version"] = tool_version
        if "schema_version" not in record_value:
            record_value["schema_version"] = 1
        return cls.from_store_value(
            namespace=namespace,
            key=key,
            value=record_value,
            created_at=utc_now_iso(),
        )

    def to_store_value(self) -> dict[str, Any]:
        return {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name not in _STORE_METADATA_FIELDS
        }

    @classmethod
    def from_store_value(
        cls,
        *,
        namespace: Namespace,
        key: str,
        value: dict[str, Any],
        created_at: str,
    ) -> "MemoryRecord":
        values = {
            field.name: value[field.name]
            for field in fields(cls)
            if field.name not in _STORE_METADATA_FIELDS and field.name in value
        }
        return cls(
            namespace=namespace,
            key=key,
            created_at=created_at,
            **values,
        )
