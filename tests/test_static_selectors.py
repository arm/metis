# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.analysis.static_inventory import StaticInventory, StaticUnit
from metis.engine.analysis.static_selectors import (
    inventory_summary,
    llm_candidate_units,
    top_risky_units,
    units_by_risk_level,
    units_for_file,
    units_with_unknown_obligations,
)


def _unit(unit_id, file_path, score, level, *, should_call_llm=False, unknown=False):
    obligations = []
    if unknown:
        obligations.append(
            {
                "name": "bounds_or_capacity",
                "status": "unknown",
                "evidence": [],
                "unresolved_hops": [],
                "needed_context": ["find bounds"],
            }
        )
    return StaticUnit(
        unit_id=unit_id,
        file_path=file_path,
        kind="function",
        name=unit_id.rsplit("::", 1)[-1],
        start_line=1,
        end_line=2,
        analysis={
            "risk": {
                "score": score,
                "level": level,
                "should_call_llm": should_call_llm,
            },
            "obligations": obligations,
        },
    )


def test_static_selectors_filter_units():
    inventory = StaticInventory(
        version=1,
        generated_at="now",
        codebase_path="/repo",
        units={
            "a": _unit("a", "src/a.c", 80, "high", should_call_llm=True, unknown=True),
            "b": _unit("b", "src/a.c", 45, "medium"),
            "c": _unit("c", "src/b.c", 10, "low"),
        },
    )

    assert [unit.unit_id for unit in units_for_file(inventory, "src/a.c")] == ["a", "b"]
    assert [unit.unit_id for unit in units_by_risk_level(inventory, "high")] == ["a"]
    assert [unit.unit_id for unit in llm_candidate_units(inventory)] == ["a"]
    assert [unit.unit_id for unit in units_with_unknown_obligations(inventory)] == ["a"]
    assert [unit.unit_id for unit in top_risky_units(inventory, limit=2)] == ["a", "b"]


def test_inventory_summary_counts_analysis_fields():
    inventory = StaticInventory(
        version=1,
        generated_at="now",
        codebase_path="/repo",
        files={"src/a.c": object(), "src/b.c": object()},
        units={
            "a": _unit("a", "src/a.c", 80, "high", should_call_llm=True, unknown=True),
            "b": _unit("b", "src/a.c", 45, "medium", unknown=True),
            "c": _unit("c", "src/b.c", 0, "none"),
        },
        symbols={"a": {"definitions": ["a"], "references": []}},
        call_edges=[{"caller": "a", "callee_symbol": "b"}],
    )

    summary = inventory_summary(inventory)

    assert summary["files"] == 2
    assert summary["units"] == 3
    assert summary["symbols"] == 1
    assert summary["call_edges"] == 1
    assert summary["high_risk_units"] == 1
    assert summary["medium_risk_units"] == 1
    assert summary["llm_candidate_units"] == 1
    assert summary["units_with_unknown_obligations"] == 2
    assert summary["unknown_obligations"] == 2
