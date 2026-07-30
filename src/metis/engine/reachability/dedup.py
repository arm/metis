# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from collections import defaultdict

from metis.engine.prompt_catalog import get_engine_prompts

from .finding_accessors import _finding_file
from .finding_accessors import _finding_function
from .finding_values import _safe_int
from .limits import FINAL_DEDUP_BATCH_SIZE
from .limits import FINAL_DEDUP_REPRESENTATIVE_BATCH_SIZE
from .workers import run_reachability_jobs

FINAL_CONSOLIDATION_SYSTEM_PROMPT = get_engine_prompts("reachability_dedup")["system"]


class FindingConsolidator:
    @staticmethod
    def deduplicate(
        findings,
        *,
        max_per_sink=3,
        final_adjudicator=None,
        representative_scope="file",
        final_adjudication_progress=None,
        max_workers=1,
    ):
        if not findings:
            return [], 0, 0

        total = len(findings)
        original = list(findings)
        adjudicated = _apply_final_adjudication(
            original,
            final_adjudicator,
            representative_scope=representative_scope,
            progress_callback=final_adjudication_progress,
            max_workers=max_workers,
        )
        if adjudicated is not None:
            return adjudicated, total, total - len(adjudicated)
        return original, total, 0


Deduplicator = FindingConsolidator


def _apply_final_adjudication(
    findings,
    adjudicator,
    *,
    representative_scope="file",
    progress_callback=None,
    max_workers=1,
):
    if not callable(adjudicator) or not findings:
        return None
    if len(findings) < 2:
        return findings

    payloads = [
        _finding_adjudication_payload(index, finding)
        for index, finding in enumerate(findings)
    ]
    original_limit = len(findings)
    merged = _UnionFind(original_limit)
    representative_preferences = []
    saw_valid_decision = False

    initial_batches = _adjudication_batches(payloads)
    if _run_adjudication_batches(
        initial_batches,
        adjudicator,
        merged,
        representative_preferences,
        original_limit,
        progress_callback=progress_callback,
        phase="candidate",
        max_workers=max_workers,
    ):
        saw_valid_decision = True

    representative_payloads = [
        payloads[index]
        for index in _representative_indexes(merged, representative_preferences)
    ]
    if (
        representative_scope
        and len(representative_payloads) > 1
        and len(payloads) > FINAL_DEDUP_BATCH_SIZE
    ):
        representative_batches = _adjudication_batches(
            representative_payloads,
            batch_size=FINAL_DEDUP_REPRESENTATIVE_BATCH_SIZE,
            scope=representative_scope,
        )
        if _run_adjudication_batches(
            representative_batches,
            adjudicator,
            merged,
            representative_preferences,
            original_limit,
            progress_callback=progress_callback,
            phase="representative",
            max_workers=max_workers,
        ):
            saw_valid_decision = True

    if not saw_valid_decision:
        return None

    keep_indexes = set(_representative_indexes(merged, representative_preferences))
    return [finding for index, finding in enumerate(findings) if index in keep_indexes]


def _run_adjudication_batches(
    batches,
    adjudicator,
    merged,
    representative_preferences,
    original_limit,
    *,
    progress_callback=None,
    phase="candidate",
    max_workers=1,
):
    if not batches:
        return False

    total = len(batches)
    if progress_callback:
        progress_callback({"phase": phase, "completed": 0, "total": total})
    batch_results = run_reachability_jobs(
        list(enumerate(batches)),
        lambda item: (item[0], adjudicator(item[1])),
        max_workers=max_workers,
        label="Final reachability adjudication",
        result_key=lambda item: f"{phase}:{item[0]}",
        on_complete=lambda _key, completed, total: (
            progress_callback({"phase": phase, "completed": completed, "total": total})
            if progress_callback
            else None
        ),
        swallow_exceptions=False,
    )
    saw_valid_decision = False
    for _index, decision in sorted(batch_results, key=lambda item: item[0]):
        if _merge_decision_groups(
            merged,
            representative_preferences,
            decision,
            original_limit,
        ):
            saw_valid_decision = True
    return saw_valid_decision


def _adjudication_batches(
    payloads,
    *,
    batch_size=FINAL_DEDUP_BATCH_SIZE,
    scope="function",
):
    if len(payloads) < 2:
        return []
    if len(payloads) <= batch_size:
        return [payloads]
    batches = []
    by_scope = defaultdict(list)
    for payload in sorted(payloads, key=_payload_sort_key):
        by_scope[_payload_scope_key(payload, scope)].append(payload)
    for scope_payloads in by_scope.values():
        if len(scope_payloads) < 2:
            continue
        batches.extend(_chunk_payloads(scope_payloads, batch_size))
    return batches


def _chunk_payloads(payloads, size):
    chunks = [payloads[index : index + size] for index in range(0, len(payloads), size)]
    return [chunk for chunk in chunks if len(chunk) > 1]


def _payload_scope_key(payload, scope):
    file_path = str(payload.get("primary_file") or "")
    if scope == "file":
        return (file_path,)
    return (file_path, str(payload.get("primary_function") or ""))


def _payload_sort_key(payload):
    return (
        str(payload.get("primary_file") or ""),
        str(payload.get("primary_function") or ""),
        int(payload.get("index") or 0),
    )


def _representative_indexes(merged, representative_preferences):
    representatives = []
    for members in merged.groups().values():
        representative = _preferred_representative(members, representative_preferences)
        representatives.append(representative)
    return sorted(representatives)


def _preferred_representative(members, representative_preferences):
    member_set = set(members)
    for representative in reversed(representative_preferences):
        if representative in member_set:
            return representative
    return min(members)


def _merge_decision_groups(
    merged,
    representative_preferences,
    decision,
    original_limit,
):
    if not isinstance(decision, dict):
        return False
    groups = decision.get("groups")
    if not isinstance(groups, list):
        return False

    accepted = False
    for group in groups:
        if not isinstance(group, dict):
            continue
        relationship = str(group.get("relationship") or "").strip().lower()
        if relationship and relationship != "duplicate":
            continue
        members = _valid_member_indexes(group.get("member_indexes"), original_limit)
        if len(members) < 2:
            continue
        representative = _representative_index(
            group.get("representative_index"), members
        )
        if representative is None:
            representative = min(members)
        else:
            representative_preferences.append(representative)
        for member in members:
            merged.union(representative, member)
        accepted = True
    return accepted


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


def _representative_index(raw, members):
    index = _safe_int(raw, -1)
    return index if index in members else None


def _finding_adjudication_payload(index, finding):
    return {
        "index": index,
        "description": str(getattr(finding, "description", "") or ""),
        "root_cause": str(getattr(finding, "root_cause", "") or "")[:800],
        "evidence": str(getattr(finding, "evidence", "") or "")[:900],
        "primary_file": _finding_file(finding),
        "primary_function": _finding_function(finding),
    }
