# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from .review_risk import UnitRisk
from .static_xref import UnitXref

ObligationStatus = Literal["covered", "missing", "unknown"]

MEMORY_SIGNALS = {
    "copy_or_format",
    "pointer_arithmetic",
    "array_index",
    "mmio_or_register",
}
INPUT_SIGNALS = {"parser_or_decoder"}
VALIDATION_SIGNALS = {"auth_or_policy"}
LIFETIME_SIGNALS = {"allocation_or_free"}
CONCURRENCY_SIGNALS = {"lock_or_concurrency"}

VALIDATION_TERMS = (
    "auth",
    "check",
    "permission",
    "policy",
    "sanitize",
    "valid",
    "verify",
)
BOUND_TERMS = ("bound", "cap", "capacity", "end", "limit", "max", "size")
ALLOC_TERMS = ("alloc", "calloc", "malloc", "new", "realloc")
FREE_TERMS = ("delete", "free", "release")
LOCK_TERMS = ("lock", "mutex", "spinlock")
UNLOCK_TERMS = ("unlock",)


@dataclass
class ReviewObligation:
    name: str
    status: ObligationStatus = "unknown"
    evidence: list[str] = field(default_factory=list)
    unresolved_hops: list[str] = field(default_factory=list)
    needed_context: list[str] = field(default_factory=list)


def derive_obligations(unit: Any, xref: UnitXref, risk: UnitRisk) -> list[str]:
    signals = set(unit.risk_signals)
    obligations: list[str] = []

    if risk.score > 0:
        obligations.append("reachability")
    if signals & MEMORY_SIGNALS:
        obligations.append("bounds_or_capacity")
    if signals & INPUT_SIGNALS:
        obligations.append("input_trust_boundary")
    if signals & VALIDATION_SIGNALS:
        obligations.append("validation_or_authorization")
    if signals & LIFETIME_SIGNALS:
        obligations.append("memory_lifetime")
    if signals & CONCURRENCY_SIGNALS:
        obligations.append("concurrency_or_locking")
    if xref.unresolved_calls or "indirect_call" in signals:
        obligations.append("indirect_call_resolution")
    if xref.macro_uses:
        obligations.append("macro_or_type_semantics")

    return _dedup(obligations)


def resolve_obligations(
    unit: Any,
    xref: UnitXref,
    obligation_names: list[str],
) -> list[ReviewObligation]:
    return [_resolve_obligation(unit, xref, name) for name in obligation_names]


def build_unit_obligations(
    unit: Any,
    xref: UnitXref,
    risk: UnitRisk,
) -> list[ReviewObligation]:
    return resolve_obligations(unit, xref, derive_obligations(unit, xref, risk))


def _resolve_obligation(
    unit: Any,
    xref: UnitXref,
    name: str,
) -> ReviewObligation:
    if name == "reachability":
        return _resolve_reachability(xref)
    if name == "bounds_or_capacity":
        return _resolve_bounds(unit, xref)
    if name == "input_trust_boundary":
        return _unknown(
            name, "identify whether parameters/data are externally controlled"
        )
    if name == "validation_or_authorization":
        return _resolve_validation(unit)
    if name == "memory_lifetime":
        return _resolve_lifetime(unit)
    if name == "concurrency_or_locking":
        return _resolve_concurrency(unit)
    if name == "indirect_call_resolution":
        return _resolve_indirect_calls(xref)
    if name == "macro_or_type_semantics":
        return _resolve_macro_context(xref)
    return _unknown(name, "unsupported obligation")


def _resolve_reachability(xref: UnitXref) -> ReviewObligation:
    if xref.callers:
        evidence = [
            f"{caller.get('caller_name') or caller.get('caller')} calls this unit"
            for caller in xref.callers[:5]
        ]
        return ReviewObligation("reachability", status="covered", evidence=evidence)
    return _unknown("reachability", "find callers, exports, callbacks, or entry points")


def _resolve_bounds(unit: Any, xref: UnitXref) -> ReviewObligation:
    refs = _all_terms(unit.references + xref.macro_uses + xref.macro_definitions)
    if any(_contains_term(ref, BOUND_TERMS) for ref in refs):
        evidence = [
            f"bound-like reference: {ref}"
            for ref in refs
            if _contains_term(ref, BOUND_TERMS)
        ]
        return ReviewObligation(
            "bounds_or_capacity", status="covered", evidence=evidence[:5]
        )
    return _unknown(
        "bounds_or_capacity",
        "find capacity, size, limit, max, or range checks tied to write/copy/index",
    )


def _resolve_validation(unit: Any) -> ReviewObligation:
    calls = _all_terms(unit.calls)
    matches = [call for call in calls if _contains_term(call, VALIDATION_TERMS)]
    if matches:
        return ReviewObligation(
            "validation_or_authorization",
            status="covered",
            evidence=[f"validation-like call: {call}" for call in matches[:5]],
        )
    return _unknown(
        "validation_or_authorization",
        "find validation, sanitization, authorization, policy, or state checks",
    )


def _resolve_lifetime(unit: Any) -> ReviewObligation:
    calls = _all_terms(unit.calls)
    has_alloc = any(_contains_term(call, ALLOC_TERMS) for call in calls)
    has_free = any(_contains_term(call, FREE_TERMS) for call in calls)
    if has_alloc and has_free:
        return ReviewObligation(
            "memory_lifetime",
            status="covered",
            evidence=["allocation and release-like calls both appear in unit"],
        )
    return _unknown("memory_lifetime", "find allocation ownership and cleanup paths")


def _resolve_concurrency(unit: Any) -> ReviewObligation:
    terms = _all_terms(unit.calls + unit.references)
    has_lock = any(_contains_term(term, LOCK_TERMS) for term in terms)
    has_unlock = any(_contains_term(term, UNLOCK_TERMS) for term in terms)
    if has_lock and has_unlock:
        return ReviewObligation(
            "concurrency_or_locking",
            status="covered",
            evidence=["lock-like and unlock-like terms both appear in unit"],
        )
    return _unknown("concurrency_or_locking", "find lock/atomic/refcount discipline")


def _resolve_indirect_calls(xref: UnitXref) -> ReviewObligation:
    if xref.unresolved_calls:
        return ReviewObligation(
            "indirect_call_resolution",
            status="unknown",
            unresolved_hops=[
                f"CALL_TARGET_UNRESOLVED:{call}" for call in xref.unresolved_calls
            ],
            needed_context=[
                "resolve function pointer, callback, dispatch table, or external callee target"
            ],
        )
    return ReviewObligation(
        "indirect_call_resolution",
        status="covered",
        evidence=["all calls in unit have local symbol definitions"],
    )


def _resolve_macro_context(xref: UnitXref) -> ReviewObligation:
    unresolved = [
        macro for macro in xref.macro_uses if macro not in xref.macro_definitions
    ]
    if unresolved:
        return ReviewObligation(
            "macro_or_type_semantics",
            status="unknown",
            unresolved_hops=[
                f"MACRO_DEFINITION_UNRESOLVED:{macro}" for macro in unresolved
            ],
            needed_context=["resolve macro/type definition affecting unit semantics"],
        )
    return ReviewObligation(
        "macro_or_type_semantics",
        status="covered",
        evidence=[
            f"macro definition present: {macro}" for macro in xref.macro_uses[:5]
        ],
    )


def _unknown(name: str, needed_context: str) -> ReviewObligation:
    return ReviewObligation(name, status="unknown", needed_context=[needed_context])


def _all_terms(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in out:
            out.append(text)
    return out


def _contains_term(value: str, terms: tuple[str, ...]) -> bool:
    lowered = str(value or "").lower()
    return any(term in lowered for term in terms)


def _dedup(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        if value not in out:
            out.append(value)
    return out
