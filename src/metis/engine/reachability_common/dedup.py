# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Deterministic deduplication for reachability findings."""

from __future__ import annotations

import re
from collections import defaultdict

from .finding_normalization import (
    _VTYPE_FAMILY,
    _finding_file,
    _finding_function,
    _finding_line,
    _normalise_vuln_type,
)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}
_VULN_PRIORITY = {
    "use_after_free": 0,
    "double_free": 0,
    "double_close": 0,
    "teardown_race": 0,
    "stale_pointer_after_realloc": 0,
    "format_string": 0,
    "out_of_bounds": 0,
    "buffer_overflow": 0,
    "integer_overflow": 0,
    "integer_overflow_in_allocation": 0,
    "missing_auth": 0,
    "permission_mismatch": 0,
    "auth_comparison_logic_error": 0,
    "refcount_imbalance": 1,
    "missing_bounds_check": 1,
    "boolean_coercion": 1,
    "info_leak": 1,
    "type_confusion": 1,
    "state_order": 2,
    "null_deref": 3,
}
_LINE_BUCKET_SIZE = 5


class Deduplicator:
    @staticmethod
    def deduplicate(findings, *, max_per_sink=3):
        """
        Collapse duplicate reachability findings using stable model-owned fields.

        The LLM prompt requires a canonical key for each distinct root cause. When
        that key is absent, fall back to the deterministic primary location and
        normalized vulnerability family. This intentionally avoids prose/token
        matching so different bugs in the same area are not merged by wording.
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
    return finding


def _collapse_by_canonical_identity(findings):
    keyed_groups = defaultdict(list)
    fallback_groups = defaultdict(list)

    for finding in findings:
        canonical_key = _canonical_key(finding)
        if canonical_key:
            keyed_groups[canonical_key].append(finding)
            continue
        fallback_groups[_fallback_identity_key(finding)].append(finding)

    collapsed = []
    for group in keyed_groups.values():
        collapsed.append(_pick_best(group))
    for group in fallback_groups.values():
        collapsed.append(_pick_best(group))
    return collapsed


def _canonical_key(finding):
    raw = str(getattr(finding, "canonical_key", "") or "").strip().lower()
    if not raw:
        return ""
    return re.sub(r"\s+", "", raw).replace("\\", "/")


def _fallback_identity_key(finding):
    line = _finding_line(finding)
    return (
        _normalize_path(_finding_file(finding)),
        _normalize_function(_finding_function(finding)),
        _dedupe_family(finding),
        _line_bucket(line),
    )


def _normalize_path(path):
    return str(path or "").strip().replace("\\", "/").lstrip("./")


def _normalize_function(function):
    return str(function or "").strip()


def _dedupe_family(finding):
    vtype = _normalise_vuln_type(getattr(finding, "vulnerability_type", ""))
    return _VTYPE_FAMILY.get(vtype, vtype)


def _line_bucket(line):
    line = max(0, int(line or 0))
    if line <= 0:
        return 0
    return (line - 1) // _LINE_BUCKET_SIZE


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
        selected.extend(_select_diverse(group, limit))
    return selected


def _pick_best(findings):
    best = min(findings, key=_best_finding_sort_key)
    best.vulnerability_type = _normalise_vuln_type(best.vulnerability_type)
    return best


def _best_finding_sort_key(finding):
    return (
        _SEVERITY_RANK.get(str(getattr(finding, "severity", "")).lower(), 5),
        _VULN_PRIORITY.get(
            _normalise_vuln_type(getattr(finding, "vulnerability_type", "")), 2
        ),
        _CONFIDENCE_RANK.get(str(getattr(finding, "confidence", "")).lower(), 3),
        len(getattr(finding, "path", []) or []),
        -len(str(getattr(finding, "description", "") or "")),
    )


def _select_diverse(findings, limit):
    if len(findings) <= limit:
        return list(findings)
    ranked = sorted(findings, key=_best_finding_sort_key)
    selected, covered_path_nodes = [], set()
    for finding in ranked:
        if len(selected) >= limit:
            break
        path_nodes = set(getattr(finding, "path", []) or [])
        if not selected or path_nodes - covered_path_nodes:
            selected.append(finding)
            covered_path_nodes.update(path_nodes)
    if len(selected) < limit:
        selected_ids = {id(finding) for finding in selected}
        for finding in ranked:
            if id(finding) not in selected_ids:
                selected.append(finding)
            if len(selected) >= limit:
                break
    return selected
