# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any


def _as_tuple(values: Iterable[Any] | None) -> tuple[str, ...]:
    return tuple(
        str(value).strip().lower() for value in values or () if str(value).strip()
    )


def _as_mapping(value: Any, *, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"Capability operation {field_name} must be a YAML mapping")
    return dict(value)


@dataclass(frozen=True, slots=True)
class CapabilityOperationManifest:
    id: str
    name: str
    description: str = ""
    surfaces: tuple[str, ...] = ()
    operation: str | None = None
    input_schema: dict[str, Any] = field(default_factory=dict)
    status: str = "active"

    def __post_init__(self) -> None:
        capability_id = str(self.id or "").strip().lower()
        name = str(self.name or "").strip()
        if not capability_id:
            raise ValueError("Capability operation id is required")
        if not name:
            raise ValueError(f"Capability operation {capability_id!r} requires a name")
        object.__setattr__(self, "id", capability_id)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "surfaces", _as_tuple(self.surfaces))
        object.__setattr__(self, "status", str(self.status or "active").strip().lower())
        if self.operation is not None:
            object.__setattr__(self, "operation", str(self.operation).strip() or None)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CapabilityOperationManifest":
        return cls(
            id=str(data.get("id") or ""),
            name=str(data.get("name") or ""),
            description=str(data.get("description") or ""),
            surfaces=tuple(data.get("surfaces") or ()),
            operation=data.get("operation"),
            input_schema=_as_mapping(
                data.get("input_schema"), field_name="input_schema"
            ),
            status=str(data.get("status") or "active"),
        )


@dataclass(frozen=True, slots=True)
class CapabilityManifest:
    name: str
    status: str = "active"
    contracts: dict[str, str] = field(default_factory=dict)
    operations: tuple[CapabilityOperationManifest, ...] = ()

    def __post_init__(self) -> None:
        name = str(self.name or "").strip().lower()
        if not name:
            raise ValueError("Capability manifest name is required")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "status", str(self.status or "active").strip().lower())
        object.__setattr__(
            self,
            "contracts",
            {str(k).strip(): str(v).strip() for k, v in self.contracts.items()},
        )

    @property
    def active(self) -> bool:
        return self.status == "active"

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CapabilityManifest":
        operations = tuple(
            CapabilityOperationManifest.from_mapping(item)
            for item in data.get("operations") or ()
        )
        return cls(
            name=str(data.get("name") or ""),
            status=str(data.get("status") or "active"),
            contracts=dict(data.get("contracts") or {}),
            operations=operations,
        )
