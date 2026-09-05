# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field
from types import MappingProxyType
from typing import Any

from ..execution.contracts import annotation_adapter


@dataclass(frozen=True, slots=True)
class StageContract:
    inputs: Mapping[str, Any]
    required_outputs: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for port in (*self.inputs, *self.required_outputs):
            if not isinstance(port, str) or not port.isidentifier():
                raise ValueError(f"Execution stage contract has invalid port {port!r}")
        for port, annotation in (*self.inputs.items(), *self.required_outputs.items()):
            try:
                annotation_adapter(annotation)
            except Exception as exc:
                raise TypeError(
                    f"Execution stage contract port {port!r} has an unsupported "
                    f"annotation: {annotation!r}"
                ) from exc
        object.__setattr__(
            self,
            "inputs",
            MappingProxyType(dict(self.inputs)),
        )
        object.__setattr__(
            self,
            "required_outputs",
            MappingProxyType(dict(self.required_outputs)),
        )


@dataclass(frozen=True, slots=True)
class StageRegistration:
    name: str
    contract: StageContract

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.isidentifier():
            raise ValueError(f"Invalid execution stage name: {self.name!r}")
        if not isinstance(self.contract, StageContract):
            raise TypeError("Execution stage contract must be a StageContract")
