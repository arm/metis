# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Deterministic deduplication for reachability findings."""

from __future__ import annotations

from collections import defaultdict

from .finding_normalization import (
    _canonical_finding_key,
    _finding_file,
    _finding_function,
    _finding_line,
    _normalise_vuln_type,
)
from .finding_taxonomy import _VTYPE_FAMILY

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


class Deduplicator:
    @staticmethod
    def deduplicate(findings, *, max_per_sink=3):
        """
        Collapse duplicate reachability findings using stable canonical fields.

        Parsers normalize model output into a deterministic canonical key built from
        primary file/function, vulnerability family, and a short root-cause token.
        This intentionally avoids prose/token matching so different bugs in the same
        area are not merged by wording alone.
        """
        if not findings:
            return [], 0, 0

        normalized = [_normalize_finding(finding) for finding in findings]
        collapsed = _collapse_by_canonical_identity(normalized)
        selected = _cap_per_function_family(collapsed, max_per_sink)
        return selected, len(findings), len(findings) - len(selected)


def _normalize_finding(finding):
    finding.vulnerability_type = _normalise_vuln_type(
        getattr(finding, "vulnerability_type", "")
    )
    canonical_key = _canonical_finding_key(finding)
    if canonical_key:
        finding.canonical_key = canonical_key
    return finding


def _collapse_by_canonical_identity(findings):
    groups = defaultdict(list)
    for finding in findings:
        key = _canonical_finding_key(finding) or f"unkeyed:{id(finding)}"
        groups[key].append(finding)

    collapsed = []
    for group in groups.values():
        collapsed.append(_pick_best(group))
    return collapsed


def _normalize_path(path):
    return str(path or "").strip().replace("\\", "/").lstrip("./")


def _normalize_function(function):
    return str(function or "").strip()


def _dedupe_family(finding):
    vtype = _normalise_vuln_type(getattr(finding, "vulnerability_type", ""))
    return _VTYPE_FAMILY.get(vtype, vtype)


def _cap_per_function_family(findings, limit):
    limit = max(1, int(limit or 1))
    groups = defaultdict(list)
    for finding in findings:
        groups[
            (
                _normalize_path(_finding_file(finding)),
                _normalize_function(_finding_function(finding)),
                _dedupe_family(finding),
            )
        ].append(finding)

    selected = []
    for group in groups.values():
        selected.extend(sorted(group, key=_best_finding_sort_key)[:limit])
    return selected


def _pick_best(findings):
    best = min(findings, key=_best_finding_sort_key)
    best.vulnerability_type = _normalise_vuln_type(best.vulnerability_type)
    return best


def _best_finding_sort_key(finding):
    canonical_key = str(getattr(finding, "canonical_key", "") or "")
    return (
        _SEVERITY_RANK.get(str(getattr(finding, "severity", "")).lower(), 5),
        _CONFIDENCE_RANK.get(str(getattr(finding, "confidence", "")).lower(), 3),
        not bool(_finding_file(finding)),
        not bool(_finding_function(finding)),
        _finding_line(finding) <= 0,
        not bool(canonical_key),
        ":line_" in canonical_key,
        len(getattr(finding, "path", []) or []),
        -len(str(getattr(finding, "description", "") or "")),
    )
