# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ModelToolSettings:
    max_rounds: int
    max_contract_chars: int


@dataclass(frozen=True, slots=True)
class TriageOptions:
    include_triaged: bool = False


@dataclass(frozen=True, slots=True)
class CapabilityRuntimeSettings:
    model_tools: ModelToolSettings
    configurations: dict[str, dict[str, Any]]
