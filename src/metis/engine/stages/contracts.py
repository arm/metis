# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from ..execution.contracts import _freeze_mappings
from ..execution.contracts import _validate_ports


@dataclass(frozen=True, slots=True)
class StageContract:
    inputs: Mapping[str, Any]
    required_outputs: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_ports(
            (*self.inputs.items(), *self.required_outputs.items()),
            owner="Execution stage contract",
            describe=lambda port: f"Execution stage contract port {port!r}",
        )
        _freeze_mappings(self, "inputs", "required_outputs")


@dataclass(frozen=True, slots=True)
class StageRegistration:
    name: str
    contract: StageContract

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.isidentifier():
            raise ValueError(f"Invalid execution stage name: {self.name!r}")
        if not isinstance(self.contract, StageContract):
            raise TypeError("Execution stage contract must be a StageContract")
