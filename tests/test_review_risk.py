# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.analysis.review_risk import score_unit_risk, should_review_with_llm
from metis.engine.analysis.static_inventory import StaticUnit
from metis.engine.analysis.static_xref import UnitXref


def test_score_unit_risk_from_static_signals():
    unit = StaticUnit(
        unit_id="src/a.c::copy_in:1-5",
        file_path="src/a.c",
        kind="function",
        name="copy_in",
        start_line=1,
        end_line=5,
        risk_signals=["copy_or_format", "array_index"],
    )

    risk = score_unit_risk(unit)

    assert risk.score == 50
    assert risk.level == "medium"
    assert should_review_with_llm(risk)


def test_score_unit_risk_includes_unresolved_calls():
    unit = StaticUnit(
        unit_id="src/a.c::dispatch:1-5",
        file_path="src/a.c",
        kind="function",
        name="dispatch",
        start_line=1,
        end_line=5,
        risk_signals=["indirect_call"],
    )
    xref = UnitXref(
        unit_id=unit.unit_id, unit=unit, unresolved_calls=["ops", "handler"]
    )

    risk = score_unit_risk(unit, xref)

    assert risk.score == 30
    assert risk.level == "low"
    assert risk.unresolved_calls == ["ops", "handler"]
    assert not should_review_with_llm(risk)


def test_score_unit_risk_caps_type_units():
    unit = StaticUnit(
        unit_id="src/a.c::State:1-20",
        file_path="src/a.c",
        kind="type",
        name="State",
        start_line=1,
        end_line=20,
        risk_signals=["copy_or_format", "mmio_or_register", "auth_or_policy"],
    )

    risk = score_unit_risk(unit)

    assert risk.score == 40
    assert risk.level == "medium"
