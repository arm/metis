# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Utilities for computing CVSS v4.0 vectors, scores, and severity."""

from __future__ import annotations

import logging
from typing import Dict

from cvss import CVSS4

logger = logging.getLogger("metis")

BASE_METRIC_ORDER = [
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
]


def normalize_metric_values(metrics: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of the metrics with upper-cased keys and values."""

    normalized: Dict[str, str] = {}
    for metric, value in metrics.items():
        if not value:
            continue
        normalized[metric.upper()] = value.strip().upper()
    return normalized


def calculate_cvss_score(metrics: Dict[str, str]) -> float:
    """Calculate the CVSS v4.0 base score using the official library."""

    normalized = normalize_metric_values(metrics)
    _ensure_required_metrics(normalized)

    vector = format_cvss_vector(normalized)
    try:
        cvss = CVSS4(vector)
    except Exception as exc:  # pragma: no cover - defensive logging path
        raise ValueError(f"Invalid CVSS vector: {exc}") from exc

    base_score = cvss.base_score
    if base_score is None:
        raise ValueError("CVSS library did not return a base score")

    return float(base_score)


def format_cvss_vector(metrics: Dict[str, str]) -> str:
    """Return a CVSS v4.0 vector string for the supplied metrics."""

    normalized = normalize_metric_values(metrics)
    parts = []
    for metric in BASE_METRIC_ORDER:
        if metric in normalized:
            parts.append(f"{metric}:{normalized[metric]}")
    return "CVSS:4.0/" + "/".join(parts)


def compute_cvss_severity(vector: str) -> str:
    """Return the qualitative severity for a CVSS vector."""

    try:
        cvss_obj = CVSS4(vector)
        severities = cvss_obj.severities()
        return severities[0] if severities else ""
    except Exception as exc:  # pragma: no cover - defensive logging path
        logger.warning("Unable to compute CVSS severity for vector %s: %s", vector, exc)
        return ""


def normalize_cvss_rating(rating) -> str:
    if not rating:
        return ""
    value = str(rating).strip().upper()
    mapping = {
        "LOW": "Low",
        "L": "Low",
        "MED": "Medium",
        "MEDIUM": "Medium",
        "MID": "Medium",
        "HIGH": "High",
        "H": "High",
        "CRITICAL": "Critical",
        "CRIT": "Critical",
        "C": "Critical",
    }
    return mapping.get(value, rating if isinstance(rating, str) else "")


def populate_cvss_data(issue: Dict) -> None:
    """Populate the ``cvss`` field on an issue dict using available metadata."""

    metrics = issue.get("cvss_metrics")
    normalized_metrics = (
        normalize_metric_values(metrics) if isinstance(metrics, dict) else None
    )

    vector = issue.get("cvss_vector")
    derived_vector = None
    if normalized_metrics:
        try:
            derived_vector = format_cvss_vector(normalized_metrics)
        except ValueError as exc:
            logger.warning("Unable to format CVSS vector from metrics: %s", exc)
            normalized_metrics = None
    if vector:
        derived_vector = vector

    severity = normalize_cvss_rating(
        issue.get("cvss_rating") or issue.get("cvss_severity")
    )
    score = None

    if derived_vector:
        try:
            cvss_obj = CVSS4(derived_vector)
            score = float(cvss_obj.base_score)
            severity_from_vector = compute_cvss_severity(derived_vector)
            if severity_from_vector:
                severity = severity_from_vector
        except Exception as exc:
            logger.warning("Invalid CVSS vector provided in review: %s", exc)
            derived_vector = None
            score = None

    if not (derived_vector or severity):
        return

    issue_cvss = issue.get("cvss")
    if not isinstance(issue_cvss, dict):
        issue_cvss = {}

    if derived_vector:
        issue_cvss["vector"] = derived_vector
    if score is not None:
        issue_cvss["score"] = score
    if severity:
        issue_cvss["severity"] = severity
    if normalized_metrics:
        issue_cvss["metrics"] = normalized_metrics

    issue["cvss"] = issue_cvss


def _ensure_required_metrics(metrics: Dict[str, str]) -> None:
    missing = [metric for metric in BASE_METRIC_ORDER if metric not in metrics]
    if missing:
        raise ValueError(
            f"Missing metrics required for CVSS base score: {', '.join(missing)}"
        )
