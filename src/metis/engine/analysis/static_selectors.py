# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any


def units_for_file(inventory: Any, file_path: str) -> list[Any]:
    return [
        unit
        for unit in inventory.units.values()
        if getattr(unit, "file_path", "") == file_path
    ]


def units_by_risk_level(inventory: Any, level: str) -> list[Any]:
    return [
        unit for unit in inventory.units.values() if _risk(unit).get("level") == level
    ]


def llm_candidate_units(inventory: Any) -> list[Any]:
    return [
        unit
        for unit in inventory.units.values()
        if bool(_risk(unit).get("should_call_llm", False))
    ]


def units_with_unknown_obligations(inventory: Any) -> list[Any]:
    return [
        unit
        for unit in inventory.units.values()
        if any(
            obligation.get("status") == "unknown" for obligation in _obligations(unit)
        )
    ]


def top_risky_units(inventory: Any, *, limit: int = 20) -> list[Any]:
    units = sorted(
        inventory.units.values(),
        key=lambda unit: (
            -int(_risk(unit).get("score") or 0),
            getattr(unit, "file_path", ""),
            getattr(unit, "start_line", 0),
        ),
    )
    return units[: max(0, limit)]


def inventory_summary(inventory: Any) -> dict[str, int]:
    unknown_obligation_count = 0
    for unit in inventory.units.values():
        unknown_obligation_count += sum(
            1
            for obligation in _obligations(unit)
            if obligation.get("status") == "unknown"
        )

    return {
        "files": len(inventory.files),
        "units": len(inventory.units),
        "symbols": len(inventory.symbols),
        "call_edges": len(inventory.call_edges),
        "high_risk_units": len(units_by_risk_level(inventory, "high")),
        "medium_risk_units": len(units_by_risk_level(inventory, "medium")),
        "llm_candidate_units": len(llm_candidate_units(inventory)),
        "units_with_unknown_obligations": len(
            units_with_unknown_obligations(inventory)
        ),
        "unknown_obligations": unknown_obligation_count,
    }


def _risk(unit: Any) -> dict[str, Any]:
    analysis = getattr(unit, "analysis", {}) or {}
    risk = analysis.get("risk") if isinstance(analysis, dict) else {}
    return risk if isinstance(risk, dict) else {}


def _obligations(unit: Any) -> list[dict[str, Any]]:
    analysis = getattr(unit, "analysis", {}) or {}
    obligations = analysis.get("obligations") if isinstance(analysis, dict) else []
    return obligations if isinstance(obligations, list) else []
