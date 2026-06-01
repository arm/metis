# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import re


def _severity_title(value, default="Medium"):
    text = str(value or "").strip().lower()
    if not text:
        return default
    return text[:1].upper() + text[1:]


def _confidence_score(value, default=0.75):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, min(1.0, round(float(value), 2)))

    text = str(value or "").strip().lower()
    if not text:
        return default
    try:
        return max(0.0, min(1.0, round(float(text), 2)))
    except ValueError:
        pass
    return {
        "very high": 0.99,
        "high": 0.95,
        "medium": 0.75,
        "moderate": 0.75,
        "low": 0.55,
        "very low": 0.35,
        "informational": 0.5,
        "info": 0.5,
    }.get(text, default)


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalise_vuln_type(raw):
    text = str(raw or "other").strip().lower().replace("-", "_").replace(" ", "_")
    text = re.sub(r"[^a-z0-9_]+", "_", text)
    return re.sub(r"_+", "_", text).strip("_") or "other"


def _mitigation_text(finding, vulnerability_type: str | None = None) -> str:
    explicit = str(getattr(finding, "mitigation", "") or "").strip()
    if explicit:
        return explicit

    vtype = _normalise_vuln_type(
        vulnerability_type or getattr(finding, "vulnerability_type", "")
    )
    label = vtype.replace("_", " ")
    return (
        f"Address the {label} issue by adding the missing validation, ordering, "
        "ownership, or cleanup guard before the reachable operation executes."
    )
