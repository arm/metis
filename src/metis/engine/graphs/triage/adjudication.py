# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations


_CONTRADICTION_SIGNALS = (
    "contradict",
    "not present",
    "cannot reproduce",
    "false positive",
    "guarded against",
    "bounded",
    "validated before use",
)

_UNCERTAINTY_SIGNALS = (
    "inconclusive",
    "cannot determine",
    "cannot be determined",
    "cannot confirm",
    "cannot refute",
    "insufficient evidence",
    "insufficient context",
    "missing definition",
    "missing implementation",
    "not enough evidence",
    "unknown",
    "uncertain",
)

NON_CRITICAL_UNRESOLVED_PREFIXES = (
    "SYMBOL_DEFINITION_UNRESOLVED:",
    "FLOW_SINK_CLASS_UNRESOLVED:",
    "FLOW_CROSS_SCOPE_CALL_REVIEW_NEEDED:",
)

CROSS_BOUNDARY_UNRESOLVED_PREFIXES = (
    "FLOW_EXTERNAL_CALLEE_UNRESOLVED:",
    "SYMBOL_DEFINITION_UNRESOLVED:",
    "FLOW_ENCLOSING_FUNCTION_UNRESOLVED",
    "FLOW_SINK_NOT_FOUND",
)


def _contains_any_signal(*texts: str, signals: tuple[str, ...]) -> bool:
    hay = "\n".join(str(t or "") for t in texts).lower()
    return any(s in hay for s in signals)


def contains_contradiction_signal(*texts: str) -> bool:
    return _contains_any_signal(*texts, signals=_CONTRADICTION_SIGNALS)


def contains_uncertainty_signal(*texts: str) -> bool:
    return _contains_any_signal(*texts, signals=_UNCERTAINTY_SIGNALS)


def is_non_critical_unresolved_hop(hop: str) -> bool:
    text = str(hop or "").strip()
    if not text:
        return False
    for prefix in NON_CRITICAL_UNRESOLVED_PREFIXES:
        if text.startswith(prefix):
            return True
    return False


def is_cross_boundary_unresolved_hop(hop: str) -> bool:
    text = str(hop or "").strip()
    if not text:
        return False
    for prefix in CROSS_BOUNDARY_UNRESOLVED_PREFIXES:
        if text.startswith(prefix):
            return True
    return False


def has_critical_unresolved_hops(
    unresolved_hops: list[str],
    resolution_chain: list[str],
) -> bool:
    if not unresolved_hops:
        return False
    if not resolution_chain:
        return True
    for hop in unresolved_hops:
        if not is_non_critical_unresolved_hop(hop):
            return True
    return False


def adjudicate_status_deterministic(
    *,
    model_status: str,
    evidence: list[str],
    resolution_chain: list[str],
    unresolved_hops: list[str],
    reason: str,
) -> str:
    has_evidence = bool(evidence)
    has_resolution = bool(resolution_chain)
    has_critical_unresolved = has_critical_unresolved_hops(
        unresolved_hops,
        resolution_chain,
    )
    reason_uncertainty = contains_uncertainty_signal(reason)

    if contains_contradiction_signal(reason) and not contains_uncertainty_signal(
        reason
    ):
        return "invalid"

    if has_critical_unresolved:
        return "inconclusive"

    if reason_uncertainty and not (
        model_status == "valid" and has_evidence and has_resolution
    ):
        return "inconclusive"

    if has_evidence and has_resolution:
        return "valid"

    return "inconclusive"


def compose_final_reason(status: str, model_status: str, model_reason: str) -> str:
    reason = str(model_reason or "").strip()
    if not reason:
        reason = "No model reason provided."
    if status == model_status:
        return reason
    return (
        f"{reason}\nDeterministic adjudication adjusted status to '{status}' "
        f"(model suggested '{model_status}')."
    )
