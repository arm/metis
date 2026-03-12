# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re

from .obligations import missing_for_status


_CONTRADICTION_SIGNALS = (
    "contradict",
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

ALLOWED_STATUSES = ("valid", "invalid", "inconclusive")


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


def has_critical_unresolved_hops(
    unresolved_hops: list[str],
    resolution_chain: list[str],
    evidence: list[str] | None = None,
) -> bool:
    if not unresolved_hops:
        return False
    if not resolution_chain:
        return True
    resolved_macros = _extract_resolved_macros(resolution_chain, evidence or [])
    for hop in unresolved_hops:
        if _is_resolved_macro_hop(hop, resolved_macros):
            continue
        if not is_non_critical_unresolved_hop(hop):
            return True
    return False


def _extract_resolved_macros(
    resolution_chain: list[str], evidence: list[str]
) -> set[str]:
    out: set[str] = set()
    for text in list(resolution_chain or []) + list(evidence or []):
        value = str(text or "")
        for match in re.findall(
            r"MACRO_RESOLUTION[^A-Za-z0-9_]*([A-Za-z_][A-Za-z0-9_]*)",
            value,
        ):
            out.add(str(match).strip())
        for match in re.findall(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*->\s*alloca\b",
            value,
            flags=re.IGNORECASE,
        ):
            out.add(str(match).strip())
        for match in re.findall(
            r"macro semantics for\s+([A-Za-z_][A-Za-z0-9_]*)\s+resolved",
            value,
            flags=re.IGNORECASE,
        ):
            out.add(str(match).strip())
    return out


def _is_resolved_macro_hop(hop: str, resolved_macros: set[str]) -> bool:
    if not resolved_macros:
        return False
    text = str(hop or "").strip()
    if not text:
        return False
    prefixes = (
        "MACRO_SEMANTICS_UNRESOLVED:",
        "MACRO_SEMANTICS_WEAK:",
        "MACRO_DEFINITION_UNRESOLVED:",
    )
    for prefix in prefixes:
        if not text.startswith(prefix):
            continue
        suffix = text[len(prefix) :]
        macro = suffix.split(":", 1)[0].strip()
        return macro in resolved_macros
    return False


def _should_relax_invalid_constraint_gate(
    *,
    status: str,
    status_missing: list[str],
    coverage: dict[str, int],
) -> bool:
    if status != "invalid":
        return False
    missing = {str(x or "").strip() for x in status_missing}
    if missing != {"constraint_or_guard"}:
        return False
    local_context = int(coverage.get("local_context", 0) or 0)
    symbol_definition = int(coverage.get("symbol_definition", 0) or 0)
    use_site = int(coverage.get("use_site", 0) or 0)
    # Preserve quality bar while avoiding noisy overrides when invalid evidence is
    # already concrete across local context, symbol identity, and concrete use-site.
    return local_context > 0 and symbol_definition > 0 and use_site > 0


def adjudicate_status_deterministic(
    *,
    model_status: str,
    evidence: list[str],
    resolution_chain: list[str],
    unresolved_hops: list[str],
    reason: str,
    obligations: list[str] | None = None,
    obligation_coverage: dict[str, int] | None = None,
) -> tuple[str, list[str]]:
    reason_codes: list[str] = []
    normalized_model_status = str(model_status or "").strip().lower()
    if normalized_model_status not in ALLOWED_STATUSES:
        normalized_model_status = "inconclusive"
        reason_codes.append("MODEL_STATUS_NORMALIZED")

    has_evidence = bool(evidence)
    has_resolution = bool(resolution_chain)
    has_critical_unresolved = has_critical_unresolved_hops(
        unresolved_hops,
        resolution_chain,
        evidence,
    )
    reason_uncertainty = contains_uncertainty_signal(reason)
    reason_contradiction = contains_contradiction_signal(reason)

    if reason_contradiction and not reason_uncertainty:
        status = "invalid"
        if status != normalized_model_status:
            reason_codes.append("OVERRIDE_CONTRADICTION_SIGNAL")
    elif has_critical_unresolved:
        status = "inconclusive"
        if status != normalized_model_status:
            reason_codes.append("OVERRIDE_CRITICAL_UNRESOLVED")
    elif normalized_model_status == "valid":
        if not has_evidence or not has_resolution:
            status = "inconclusive"
            reason_codes.append("OVERRIDE_VALID_INSUFFICIENT_EVIDENCE")
        elif reason_uncertainty:
            status = "inconclusive"
            reason_codes.append("OVERRIDE_VALID_UNCERTAINTY_SIGNAL")
        else:
            status = "valid"
    elif normalized_model_status == "invalid":
        if reason_uncertainty:
            status = "inconclusive"
            reason_codes.append("OVERRIDE_INVALID_UNCERTAINTY_SIGNAL")
        else:
            status = "invalid"
    else:
        status = "inconclusive"

    # Guardrail: never allow invalid model decisions to be upgraded directly
    # to valid without an explicit contradiction proof.
    if normalized_model_status == "invalid" and status == "valid":
        status = "invalid"
        reason_codes.append("INVARIANT_NO_INVALID_TO_VALID")

    status_missing = missing_for_status(
        status=status,
        coverage=obligation_coverage or {},
        obligations=obligations or [],
    )
    if status_missing and status in ("valid", "invalid"):
        if _should_relax_invalid_constraint_gate(
            status=status,
            status_missing=status_missing,
            coverage=obligation_coverage or {},
        ):
            status_missing = []
    if status_missing and status in ("valid", "invalid"):
        status = "inconclusive"
        reason_codes.append("OVERRIDE_OBLIGATION_COVERAGE")
        for obligation in status_missing:
            code = (
                f"MISSING_OBLIGATION_FOR_{normalized_model_status.upper()}:{obligation}"
            )
            if code not in reason_codes:
                reason_codes.append(code)

    if status != normalized_model_status and not reason_codes:
        reason_codes.append("OVERRIDE_UNSPECIFIED")
    return status, reason_codes


def compose_final_reason(
    status: str,
    model_status: str,
    model_reason: str,
    reason_codes: list[str] | None = None,
) -> str:
    reason = str(model_reason or "").strip()
    if not reason:
        reason = "No model reason provided."
    codes = [str(c).strip() for c in (reason_codes or []) if str(c).strip()]
    if status == model_status:
        if codes:
            return f"{reason}\nAdjudication reason codes: {', '.join(codes)}."
        return reason
    out = (
        f"{reason}\nDeterministic adjudication adjusted status to '{status}' "
        f"(model suggested '{model_status}')."
    )
    if codes:
        out += f"\nAdjudication reason codes: {', '.join(codes)}."
    return out
