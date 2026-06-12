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


@dataclass(frozen=True, slots=True)
class ToolCapabilityManifest:
    id: str
    name: str
    title: str = ""
    description: str = ""
    surfaces: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    provider: str | None = None
    operation: str | None = None
    input_schema: str | None = None
    output_schema: str | None = None
    status: str = "active"

    def __post_init__(self) -> None:
        capability_id = str(self.id or "").strip().lower()
        name = str(self.name or "").strip()
        if not capability_id:
            raise ValueError("Tool capability id is required")
        if not name:
            raise ValueError(f"Tool capability {capability_id!r} requires a name")
        object.__setattr__(self, "id", capability_id)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "surfaces", _as_tuple(self.surfaces))
        object.__setattr__(self, "domains", _as_tuple(self.domains))
        object.__setattr__(self, "status", str(self.status or "active").strip().lower())
        if self.provider is not None:
            object.__setattr__(self, "provider", str(self.provider).strip() or None)
        if self.operation is not None:
            object.__setattr__(self, "operation", str(self.operation).strip() or None)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ToolCapabilityManifest":
        return cls(
            id=str(data.get("id") or ""),
            name=str(data.get("name") or ""),
            title=str(data.get("title") or ""),
            description=str(data.get("description") or ""),
            surfaces=tuple(data.get("surfaces") or ()),
            domains=tuple(data.get("domains") or ()),
            provider=data.get("provider"),
            operation=data.get("operation"),
            input_schema=data.get("input_schema"),
            output_schema=data.get("output_schema"),
            status=str(data.get("status") or "active"),
        )


@dataclass(frozen=True, slots=True)
class ToolManifest:
    schema_version: int
    name: str
    title: str = ""
    description: str = ""
    implementation: str | None = None
    visibility: str = "public"
    status: str = "active"
    default_enabled: bool = False
    contracts: dict[str, str] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    capabilities: tuple[ToolCapabilityManifest, ...] = ()

    def __post_init__(self) -> None:
        name = str(self.name or "").strip().lower()
        if not name:
            raise ValueError("Tool manifest name is required")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "schema_version", int(self.schema_version or 1))
        object.__setattr__(self, "visibility", str(self.visibility or "public").lower())
        object.__setattr__(self, "status", str(self.status or "active").strip().lower())
        if self.implementation is not None:
            object.__setattr__(
                self,
                "implementation",
                str(self.implementation).strip() or None,
            )
        object.__setattr__(
            self,
            "contracts",
            {str(k).strip(): str(v).strip() for k, v in self.contracts.items()},
        )
        object.__setattr__(self, "config", dict(self.config or {}))

    @property
    def active(self) -> bool:
        return self.status == "active"

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ToolManifest":
        capabilities = tuple(
            ToolCapabilityManifest.from_mapping(item)
            for item in data.get("capabilities") or ()
        )
        return cls(
            schema_version=int(data.get("schema_version") or 1),
            name=str(data.get("name") or ""),
            title=str(data.get("title") or ""),
            description=str(data.get("description") or ""),
            implementation=data.get("implementation"),
            visibility=str(data.get("visibility") or "public"),
            status=str(data.get("status") or "active"),
            default_enabled=bool(data.get("default_enabled", False)),
            contracts=dict(data.get("contracts") or {}),
            config=dict(data.get("config") or {}),
            capabilities=capabilities,
        )
