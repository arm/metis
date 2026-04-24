# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.analysis.review_obligations import build_unit_obligations
from metis.engine.analysis.review_risk import score_unit_risk
from metis.engine.analysis.static_inventory import StaticUnit
from metis.engine.analysis.static_xref import UnitXref


def _obligations_by_name(unit, xref=None):
    xref = xref or UnitXref(unit_id=unit.unit_id, unit=unit)
    risk = score_unit_risk(unit, xref)
    obligations = build_unit_obligations(unit, xref, risk)
    return {obligation.name: obligation for obligation in obligations}


def test_memcpy_function_derives_bounds_obligation():
    unit = StaticUnit(
        unit_id="src/a.c::copy_in:1-5",
        file_path="src/a.c",
        kind="function",
        name="copy_in",
        start_line=1,
        end_line=5,
        calls=["memcpy"],
        references=["dst", "src", "len"],
        risk_signals=["copy_or_format"],
    )

    obligations = _obligations_by_name(unit)

    assert obligations["bounds_or_capacity"].status == "unknown"
    assert "capacity" in obligations["bounds_or_capacity"].needed_context[0]


def test_parser_function_derives_input_trust_boundary_obligation():
    unit = StaticUnit(
        unit_id="src/a.c::parse_packet:1-5",
        file_path="src/a.c",
        kind="function",
        name="parse_packet",
        start_line=1,
        end_line=5,
        calls=["read_header"],
        references=["request", "len"],
        risk_signals=["parser_or_decoder"],
    )

    obligations = _obligations_by_name(unit)

    assert obligations["input_trust_boundary"].status == "unknown"
    assert (
        "externally controlled" in obligations["input_trust_boundary"].needed_context[0]
    )


def test_unresolved_call_derives_indirect_call_obligation():
    unit = StaticUnit(
        unit_id="src/a.c::dispatch:1-5",
        file_path="src/a.c",
        kind="function",
        name="dispatch",
        start_line=1,
        end_line=5,
        calls=["handler"],
        references=["ops", "handler"],
        risk_signals=["indirect_call"],
    )
    xref = UnitXref(unit_id=unit.unit_id, unit=unit, unresolved_calls=["handler"])

    obligations = _obligations_by_name(unit, xref)

    assert obligations["indirect_call_resolution"].status == "unknown"
    assert obligations["indirect_call_resolution"].unresolved_hops == [
        "CALL_TARGET_UNRESOLVED:handler"
    ]


def test_macro_use_derives_macro_obligation():
    unit = StaticUnit(
        unit_id="src/a.c::copy_in:1-5",
        file_path="src/a.c",
        kind="function",
        name="copy_in",
        start_line=1,
        end_line=5,
        calls=["memcpy"],
        references=["MAX_LEN", "dst", "src"],
        risk_signals=["copy_or_format"],
    )
    xref = UnitXref(
        unit_id=unit.unit_id,
        unit=unit,
        macro_uses=["MAX_LEN"],
        macro_definitions=["MAX_LEN"],
    )

    obligations = _obligations_by_name(unit, xref)

    assert obligations["macro_or_type_semantics"].status == "covered"
    assert obligations["bounds_or_capacity"].status == "covered"


def test_low_risk_helper_derives_no_obligations():
    unit = StaticUnit(
        unit_id="src/a.c::helper:1-3",
        file_path="src/a.c",
        kind="function",
        name="helper",
        start_line=1,
        end_line=3,
        calls=[],
        references=["value"],
        risk_signals=[],
    )

    assert _obligations_by_name(unit) == {}
