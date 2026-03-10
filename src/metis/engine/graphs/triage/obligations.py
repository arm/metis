# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

_CROSS_BOUNDARY_UNRESOLVED_PREFIXES = (
    "FLOW_EXTERNAL_CALLEE_UNRESOLVED:",
    "SYMBOL_DEFINITION_UNRESOLVED:",
    "FLOW_ENCLOSING_FUNCTION_UNRESOLVED",
    "FLOW_SINK_NOT_FOUND",
)


OBLIGATION_LOCAL_CONTEXT = "local_context"
OBLIGATION_SYMBOL_DEFINITION = "symbol_definition"
OBLIGATION_USE_SITE = "use_site"
OBLIGATION_FLOW_STEP = "flow_step"
OBLIGATION_CONSTRAINT_OR_GUARD = "constraint_or_guard"
OBLIGATION_INDIRECTION_RESOLUTION = "indirection_resolution"

BASE_REQUIRED_OBLIGATIONS = (
    OBLIGATION_LOCAL_CONTEXT,
    OBLIGATION_SYMBOL_DEFINITION,
    OBLIGATION_USE_SITE,
)

STATUS_REQUIRED_OBLIGATIONS = {
    "valid": (
        OBLIGATION_LOCAL_CONTEXT,
        OBLIGATION_SYMBOL_DEFINITION,
        OBLIGATION_USE_SITE,
        OBLIGATION_FLOW_STEP,
    ),
    "invalid": (
        OBLIGATION_LOCAL_CONTEXT,
        OBLIGATION_SYMBOL_DEFINITION,
        OBLIGATION_CONSTRAINT_OR_GUARD,
    ),
}

SECTION_OBLIGATION_MAP = {
    "FILE_WINDOW": OBLIGATION_LOCAL_CONTEXT,
    "REPORTED_LINE": OBLIGATION_LOCAL_CONTEXT,
    "ANALYZER_CITATIONS": OBLIGATION_SYMBOL_DEFINITION,
    "ANALYZER_RESOLUTION_CHAIN": OBLIGATION_SYMBOL_DEFINITION,
    "SYMBOL_RESOLUTION_HINTS": OBLIGATION_SYMBOL_DEFINITION,
    "GREP ": OBLIGATION_USE_SITE,
    "RELATED_GREP": OBLIGATION_USE_SITE,
    "SYMBOL_GREP": OBLIGATION_SYMBOL_DEFINITION,
    "MACRO_DEFINE_GREP": OBLIGATION_SYMBOL_DEFINITION,
    "MACRO_DEFINE_CONTEXT": OBLIGATION_SYMBOL_DEFINITION,
    "MACRO_RESOLUTION": OBLIGATION_SYMBOL_DEFINITION,
    "HIT_CONTEXT": OBLIGATION_USE_SITE,
    "ANALYZER_FLOW_CHAIN": OBLIGATION_FLOW_STEP,
}


def derive_obligations(
    *,
    analyzer_supported: bool,
    analyzer_unresolved_hops: list[str],
) -> list[str]:
    obligations: list[str] = list(BASE_REQUIRED_OBLIGATIONS)
    if analyzer_supported:
        obligations.append(OBLIGATION_FLOW_STEP)
    if any(is_cross_boundary_unresolved_hop(hop) for hop in analyzer_unresolved_hops):
        obligations.append(OBLIGATION_INDIRECTION_RESOLUTION)
    return _dedupe_preserve_order(obligations)


def classify_unresolved_hops(unresolved_hops: list[str]) -> dict[str, int]:
    taxonomy = {
        "cross_boundary": 0,
        "missing_definition": 0,
        "sink_not_found": 0,
        "other": 0,
    }
    for hop in unresolved_hops:
        text = str(hop or "").strip()
        if not text:
            continue
        if is_cross_boundary_unresolved_hop(text):
            taxonomy["cross_boundary"] += 1
        elif text.startswith("SYMBOL_DEFINITION_UNRESOLVED:"):
            taxonomy["missing_definition"] += 1
        elif text.startswith("FLOW_SINK_NOT_FOUND"):
            taxonomy["sink_not_found"] += 1
        else:
            taxonomy["other"] += 1
    return taxonomy


def compute_obligation_coverage(
    *,
    obligations: list[str],
    sections: list[str],
    unresolved_hops: list[str],
    has_definition_hints: bool,
) -> tuple[dict[str, int], list[str]]:
    coverage = {name: 0 for name in obligations}
    for section in sections:
        label = _extract_section_label(section)
        if not label:
            continue
        matched = _map_label_to_obligation(label)
        if matched is None:
            continue
        if matched in coverage:
            coverage[matched] += 1

    if has_definition_hints and OBLIGATION_SYMBOL_DEFINITION in coverage:
        coverage[OBLIGATION_SYMBOL_DEFINITION] += 1
    if unresolved_hops and OBLIGATION_INDIRECTION_RESOLUTION in coverage:
        # unresolved hops are evidence that an indirection path exists;
        # keep this weakly covered, but not sufficient alone for "full coverage".
        coverage[OBLIGATION_INDIRECTION_RESOLUTION] = max(
            coverage[OBLIGATION_INDIRECTION_RESOLUTION],
            1,
        )

    missing = [name for name in obligations if int(coverage.get(name, 0) or 0) <= 0]
    return coverage, missing


def required_obligations_for_status(status: str) -> list[str]:
    normalized = str(status or "").strip().lower()
    return list(STATUS_REQUIRED_OBLIGATIONS.get(normalized, ()))


def missing_for_status(
    *,
    status: str,
    coverage: dict[str, int],
    obligations: list[str],
) -> list[str]:
    if not obligations:
        return []
    required = required_obligations_for_status(status)
    if not required:
        return []
    allowed = set(obligations)
    missing: list[str] = []
    for name in required:
        if name not in allowed:
            missing.append(name)
            continue
        if int(coverage.get(name, 0) or 0) <= 0:
            missing.append(name)
    return missing


def _extract_section_label(section: str) -> str:
    if not section.startswith("["):
        return ""
    raw = section[1:].split("]", 1)[0]
    return str(raw or "").strip().upper()


def _map_label_to_obligation(label: str) -> str | None:
    for prefix, obligation in SECTION_OBLIGATION_MAP.items():
        if label.startswith(prefix):
            return obligation
    return None


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def is_cross_boundary_unresolved_hop(hop: str) -> bool:
    text = str(hop or "").strip()
    if not text:
        return False
    for prefix in _CROSS_BOUNDARY_UNRESOLVED_PREFIXES:
        if text.startswith(prefix):
            return True
    return False
