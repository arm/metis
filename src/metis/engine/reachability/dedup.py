# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Final consolidation for reachability findings."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

from .finding_normalization import (
    _finding_file,
    _finding_function,
    _finding_line,
)

FINAL_CONSOLIDATION_SYSTEM_PROMPT = """You deduplicate reachability security findings before the final report.

You receive the candidate findings for one review scope. Your task is only to
identify findings that are the same, look the same, or point to the same
underlying issue.

Do not classify, reprioritize, rewrite, merge fields, add findings, or change any
values. Do not suppress findings because they are weak, low severity, hard to
exploit, or outside a preferred vulnerability class. Keep every non-duplicate
finding exactly as-is.

For duplicates:
- A duplicate can still be a valid finding. It is duplicate when it describes
  the same underlying defect, the same unsafe state, or the same required fix.
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

The input indexes are zero-based. For each duplicate group, return all duplicate
member_indexes in ascending order. The first/lowest index in each duplicate group
is the finding that will be kept; every later member will be dropped unchanged.

Return JSON only:
{
  "groups": [
    {
      "member_indexes": [0, 3, 4],
      "relationship": "duplicate",
      "reason": "One concise reason these are the same issue."
    }
  ]
}"""

FINAL_DEDUP_SYSTEM_PROMPT = FINAL_CONSOLIDATION_SYSTEM_PROMPT

FinalAdjudicator = Callable[[list[dict[str, Any]]], dict[str, Any] | None]


class FindingConsolidator:
    @staticmethod
    def deduplicate(
        findings,
        *,
        max_per_sink=3,
        final_adjudicator=None,
    ):
        """
        Drop only later duplicate findings identified by final_adjudicator.

        This function does not classify, normalize, rewrite, cap, or merge fields.
        If no valid LLM duplicate grouping is available, the input findings are kept
        unchanged.
        """
        if not findings:
            return [], 0, 0

        total = len(findings)
        original = list(findings)
        adjudicated = _apply_final_adjudication(original, final_adjudicator)
        if adjudicated is not None:
            return adjudicated, total, total - len(adjudicated)
        return original, total, 0


Deduplicator = FindingConsolidator


def _apply_final_adjudication(findings, adjudicator):
    if not callable(adjudicator) or not findings:
        return None
    if len(findings) < 2:
        return findings

    decision = adjudicator(
        [
            _finding_adjudication_payload(index, finding)
            for index, finding in enumerate(findings)
        ]
    )
    if not isinstance(decision, dict):
        return None

    original_limit = len(findings)
    groups = decision.get("groups")
    if not isinstance(groups, list):
        return None

    merged = _UnionFind(len(findings))
    for group in groups:
        if not isinstance(group, dict):
            continue
        relationship = str(group.get("relationship") or "").strip().lower()
        if relationship and relationship != "duplicate":
            continue
        members = _valid_member_indexes(group.get("member_indexes"), original_limit)
        if len(members) < 2:
            continue
        representative = min(members)
        for member in members:
            merged.union(representative, member)

    keep_indexes = {min(members) for members in merged.groups().values()}
    return [finding for index, finding in enumerate(findings) if index in keep_indexes]


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
