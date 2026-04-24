# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .static_xref import UnitXref


RISK_WEIGHTS = {
    "copy_or_format": 30,
    "pointer_arithmetic": 25,
    "array_index": 20,
    "parser_or_decoder": 25,
    "auth_or_policy": 25,
    "allocation_or_free": 20,
    "lock_or_concurrency": 20,
    "mmio_or_register": 30,
    "indirect_call": 20,
}


@dataclass
class UnitRisk:
    unit_id: str
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)
    unresolved_calls: list[str] = field(default_factory=list)


def score_unit_risk(unit: Any, xref: UnitXref | None = None) -> UnitRisk:
    score = 0
    reasons: list[str] = []
    for signal in unit.risk_signals:
        weight = RISK_WEIGHTS.get(signal, 0)
        if weight <= 0:
            continue
        score += weight
        reasons.append(f"{signal}: +{weight}")

    unresolved_calls = list(getattr(xref, "unresolved_calls", []) or [])
    if unresolved_calls:
        unresolved_weight = min(20, 5 * len(unresolved_calls))
        score += unresolved_weight
        reasons.append(
            f"unresolved_calls({len(unresolved_calls)}): +{unresolved_weight}"
        )

    if getattr(unit, "kind", "") != "function":
        score = min(score, 40)

    score = max(0, min(100, score))
    return UnitRisk(
        unit_id=unit.unit_id,
        score=score,
        level=_risk_level(score),
        reasons=reasons,
        unresolved_calls=unresolved_calls,
    )


def should_review_with_llm(risk: UnitRisk, *, threshold: int = 50) -> bool:
    return risk.score >= threshold


def _risk_level(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "none"
