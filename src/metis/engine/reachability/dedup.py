# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Deterministic deduplication for reachability findings."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

from .finding_taxonomy import vulnerability_family
from .finding_normalization import (
    _canonical_finding_key,
    _finding_file,
    _finding_function,
    _finding_line,
    _normalise_vuln_type,
)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

FINAL_DEDUP_SYSTEM_PROMPT = """You deduplicate reachability security findings before the final report.

Your task is narrow:
- Decide only whether findings are duplicate final-report entries.
- Do not decide whether a finding is true, false, exploitable, or severe.
- A duplicate can still be a valid finding; it is duplicate if it has the same
  underlying defect and would be fixed by the same code change.
- Treat CWE, exact line numbers, analysis_type, vulnerability_type, and
  canonical_key as weak hints only. These fields may be model-generated or
  taxonomy-dependent, so they must not prevent a duplicate merge when the prose
  evidence shows the same resource, same error path, and same fix.
- Merge root-cause and later-symptom findings when the later finding is only
  evidence of the same published stale object, missing cleanup, or unbalanced
  acquire/release operation.
- Use this decision test: if one finding describes the bad action that creates
  the unsafe state (for example, publishing then freeing without rollback) and
  another describes the later consequence of that same unsafe state (for
  example, dereferencing the stale published object), merge them when the same
  rollback, ordering, or cleanup fix would address both.

Use these labels:
- duplicate: same final-report issue and same fix surface.
- related_keep_separate: related theme/resource, but distinct final-report issues.
- distinct: not the same issue.
- uncertain: insufficient evidence to merge safely.

Keep separate when findings involve different buffers, counters, callbacks,
timers, state variables, operations, or fix locations that need separate code
changes.
The same recurring bug pattern in different functions or commands is not a
duplicate unless one code change would necessarily fix all members.
When uncertain, do not merge.

Return JSON only:
{
  "groups": [
    {
      "member_indexes": [0, 1],
      "relationship": "duplicate",
      "representative_index": 0,
      "reason": "One concise reason.",
      "merged_issue": "One concise final-report issue sentence."
    }
  ]
}"""

DuplicateAdjudicator = Callable[[list[dict[str, Any]]], dict[str, Any] | None]


class Deduplicator:
    @staticmethod
    def deduplicate(findings, *, max_per_sink=3, duplicate_adjudicator=None):
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
        collapsed = _collapse_by_primary_location(collapsed)
        collapsed = _collapse_by_duplicate_adjudication(
            collapsed, duplicate_adjudicator
        )
        selected = _cap_per_function_family(collapsed, max_per_sink)
        return selected, len(findings), len(findings) - len(selected)


def _normalize_finding(finding):
    finding.vulnerability_type = _normalise_vuln_type(
        getattr(finding, "vulnerability_type", "")
    )
    canonical_key = str(getattr(finding, "canonical_key", "") or "").strip()
    if not canonical_key:
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


def _collapse_by_primary_location(findings):
    groups = defaultdict(list)
    for finding in findings:
        file_path = _normalize_path(_finding_file(finding))
        function = _normalize_function(_finding_function(finding))
        line = _finding_line(finding)
        if not file_path or not function or line <= 0:
            key = f"unlocated:{id(finding)}"
        else:
            key = (
                file_path,
                function,
                line,
                vulnerability_family(getattr(finding, "vulnerability_type", "")),
            )
        groups[key].append(finding)

    collapsed = []
    for group in groups.values():
        collapsed.append(_pick_best(group))
    return collapsed


def _normalize_path(path):
    return str(path or "").strip().replace("\\", "/").lstrip("./")


def _normalize_function(function):
    return str(function or "").strip()


def _cap_per_function_family(findings, limit):
    limit = max(1, int(limit or 1))
    groups = defaultdict(list)
    for finding in findings:
        groups[
            (
                _normalize_path(_finding_file(finding)),
                _normalize_function(_finding_function(finding)),
                vulnerability_family(getattr(finding, "vulnerability_type", "")),
            )
        ].append(finding)

    selected = []
    for group in groups.values():
        if len(group) <= limit:
            selected.extend(group)
        else:
            selected.extend(sorted(group, key=_best_finding_sort_key)[:limit])
    return selected


def _collapse_by_duplicate_adjudication(findings, adjudicator):
    if not callable(adjudicator) or len(findings) < 2:
        return findings

    decision = adjudicator(
        [
            _finding_adjudication_payload(index, finding)
            for index, finding in enumerate(findings)
        ]
    )
    if not isinstance(decision, dict):
        return findings

    groups = decision.get("groups")
    if not isinstance(groups, list):
        return findings

    merged = _UnionFind(len(findings))
    preferred: dict[int, int] = {}
    for group in groups:
        if not isinstance(group, dict):
            continue
        if str(group.get("relationship") or "").strip().lower() != "duplicate":
            continue
        members = _valid_member_indexes(group.get("member_indexes"), len(findings))
        if len(members) < 2:
            continue
        representative = _safe_int(group.get("representative_index"), members[0])
        if representative not in members:
            representative = members[0]
        for member in members:
            preferred[member] = representative
            merged.union(representative, member)

    selected = []
    for members in merged.groups().values():
        representative = next(
            (
                preferred[member]
                for member in members
                if preferred.get(member) in members
            ),
            None,
        )
        if representative is None:
            selected.append(_pick_best([findings[member] for member in members]))
        else:
            selected.append(findings[representative])
    return selected


class _UnionFind:
    def __init__(self, size):
        self._parent = list(range(size))

    def find(self, item):
        parent = self._parent[item]
        if parent != item:
            self._parent[item] = self.find(parent)
        return self._parent[item]

    def union(self, left, right):
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self._parent[right_root] = left_root

    def groups(self):
        grouped = defaultdict(list)
        for index in range(len(self._parent)):
            grouped[self.find(index)].append(index)
        return grouped


def _valid_member_indexes(raw, limit):
    if not isinstance(raw, list):
        return []
    members = []
    for value in raw:
        index = _safe_int(value, -1)
        if 0 <= index < limit and index not in members:
            members.append(index)
    return members


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _finding_adjudication_payload(index, finding):
    return {
        "index": index,
        "description": str(getattr(finding, "description", "") or ""),
        "root_cause": str(getattr(finding, "root_cause", "") or ""),
        "evidence": str(getattr(finding, "evidence", "") or "")[:2000],
        "mitigation": str(getattr(finding, "mitigation", "") or "")[:1000],
        "primary_file": _finding_file(finding),
        "primary_function": _finding_function(finding),
        "primary_line": _finding_line(finding),
        "vulnerability_type": str(getattr(finding, "vulnerability_type", "") or ""),
        "analysis_type": str(getattr(finding, "analysis_type", "") or ""),
        "cwe": str(getattr(finding, "cwe", "") or ""),
        "severity": str(getattr(finding, "severity", "") or ""),
        "confidence": getattr(finding, "confidence", None),
        "canonical_key": str(getattr(finding, "canonical_key", "") or ""),
        "path": list(getattr(finding, "path", []) or [])[:12],
    }


def _pick_best(findings):
    best = min(findings, key=_best_finding_sort_key)
    best.vulnerability_type = _normalise_vuln_type(best.vulnerability_type)
    return best


def _best_finding_sort_key(finding):
    canonical_key = str(getattr(finding, "canonical_key", "") or "")
    return (
        _SEVERITY_RANK.get(str(getattr(finding, "severity", "")).lower(), 5),
        -float(getattr(finding, "confidence", 0.0) or 0.0),
        not bool(_finding_file(finding)),
        not bool(_finding_function(finding)),
        _finding_line(finding) <= 0,
        not bool(canonical_key),
        ":line_" in canonical_key,
        len(getattr(finding, "path", []) or []),
        -len(str(getattr(finding, "description", "") or "")),
    )
