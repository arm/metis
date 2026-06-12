# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ReviewOptions:
    use_retrieval_context: bool = False


@dataclass(frozen=True, slots=True)
class TriageOptions:
    use_retrieval_context: bool = False
    include_triaged: bool = False


def normalize_top_k(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if parsed <= 0:
        return default
    return parsed
