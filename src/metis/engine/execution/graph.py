# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import model_validator

from .contracts import StageName
from .contracts import ResultFormat

InputBinding = str | tuple[str, ...]


class ConfiguredNode(BaseModel):
    inputs: dict[str, InputBinding] = Field(default_factory=dict)
    depends_on: tuple[str, ...] = ()
    max_concurrency: int | None = Field(default=None, strict=True, ge=1)
    model: str | None = Field(default=None, min_length=1)
    capabilities: tuple[str, ...] = ()
    formats: tuple[ResultFormat, ...] | None = None
    filename: str | None = Field(default=None, min_length=1)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_capabilities(self) -> "ConfiguredNode":
        if self.model is not None and not self.model.strip():
            raise ValueError("Execution node model must not be blank")
        if len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("Execution node capabilities must be unique")
        invalid = [name for name in self.capabilities if not name.isidentifier()]
        if invalid:
            raise ValueError(
                f"Execution node has invalid capabilities: {sorted(invalid)!r}"
            )
        if self.filename is not None and not self.filename.strip():
            raise ValueError("Execution node filename must not be blank")
        if self.filename is not None and not self.formats:
            raise ValueError("Execution node filename requires output formats")
        if self.filename is not None:
            output_base = Path(self.filename)
            if output_base.name in {"", ".", ".."} or output_base.suffix:
                raise ValueError(
                    "Execution node filename must be an extensionless file base"
                )
        return self


class StageConfiguration(BaseModel):
    depends_on: tuple[StageName, ...] = ()
    inputs: dict[str, str] = Field(default_factory=dict)
    outputs: tuple[str, ...] | dict[str, str] = ()
    nodes: dict[str, ConfiguredNode]

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def require_nodes(self) -> "StageConfiguration":
        if not self.nodes:
            raise ValueError("Execution stage must contain a node")
        invalid_dependencies = [
            name for name in self.depends_on if not name or not name.isidentifier()
        ]
        if invalid_dependencies:
            raise ValueError(
                "Execution stage has invalid dependencies: "
                f"{sorted(invalid_dependencies)!r}"
            )
        output_names = tuple(self.outputs)
        if len(set(output_names)) != len(output_names):
            raise ValueError("Execution stage outputs must be unique")
        invalid_outputs = [name for name in output_names if not name.isidentifier()]
        if invalid_outputs:
            raise ValueError(
                f"Execution stage has invalid outputs: {sorted(invalid_outputs)!r}"
            )
        return self


def _topological_order(
    predecessors: dict[Any, set[Any]],
    preferred_order: tuple[Any, ...],
) -> tuple[Any, ...]:
    remaining = {name: set(values) for name, values in predecessors.items()}
    order: list[Any] = []
    while remaining:
        ready = [
            name
            for name in preferred_order
            if name in remaining and not remaining[name]
        ]
        if not ready:
            cycle = ", ".join(sorted(str(name) for name in remaining))
            raise ValueError(f"Execution graph contains a cycle: {cycle}")
        for name in ready:
            order.append(name)
            del remaining[name]
        for dependencies in remaining.values():
            dependencies.difference_update(ready)
    return tuple(order)
