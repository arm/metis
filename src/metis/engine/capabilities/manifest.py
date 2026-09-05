# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields
from typing import Any


def _as_tuple(values: Iterable[Any] | None) -> tuple[str, ...]:
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)) or any(
        not isinstance(value, str) for value in values
    ):
        raise ValueError("Capability operation surfaces must be a list of strings")
    return tuple(value.strip().lower() for value in values if value.strip())


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
        for key in ("id", "name", "description", "status"):
            if not isinstance(getattr(self, key), str):
                raise ValueError(f"Capability operation {key} must be a string")
        if self.operation is not None and not isinstance(self.operation, str):
            raise ValueError("Capability operation operation must be a string")
        object.__setattr__(
            self,
            "input_schema",
            _as_mapping(self.input_schema, field_name="input_schema"),
        )
        capability_id = self.id.strip()
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
        data = _as_mapping(data, field_name="manifest")
        unknown = data.keys() - {item.name for item in fields(cls)}
        if unknown:
            raise ValueError(
                f"Unknown capability operation settings: {', '.join(sorted(map(str, unknown)))}"
            )
        return cls(**{"id": "", "name": "", **data})


@dataclass(frozen=True, slots=True)
class CapabilityManifest:
    name: str
    status: str = "active"
    contracts: dict[str, str] = field(default_factory=dict)
    operations: tuple[CapabilityOperationManifest, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not isinstance(self.status, str):
            raise ValueError("Capability manifest name and status must be strings")
        if not isinstance(self.contracts, Mapping) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in self.contracts.items()
        ):
            raise ValueError("Capability manifest contracts must map names to strings")
        if not isinstance(self.operations, (list, tuple)) or any(
            not isinstance(operation, CapabilityOperationManifest)
            for operation in self.operations
        ):
            raise ValueError(
                "Capability manifest operations must be operation manifests"
            )
        object.__setattr__(self, "operations", tuple(self.operations))
        name = self.name.strip()
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
        if not isinstance(data, Mapping):
            raise ValueError("Capability manifest must be a mapping")
        unknown = data.keys() - {item.name for item in fields(cls)}
        if unknown:
            raise ValueError(
                f"Unknown capability manifest settings: {', '.join(sorted(map(str, unknown)))}"
            )
        operations = data.get("operations", ())
        if not isinstance(operations, (list, tuple)):
            raise ValueError("Capability manifest operations must be a list")
        return cls(
            **{
                "name": "",
                **data,
                "operations": tuple(
                    CapabilityOperationManifest.from_mapping(item)
                    for item in operations
                ),
            }
        )
