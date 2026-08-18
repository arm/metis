# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import json
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from metis.engine.execution.contracts import NodeJobs
from metis.engine.stages.review.models import ReviewFinding
from metis.engine.stages.review.models import ReviewGroup
from metis.engine.stages.review.models import StandardReviewResult

PacketFits = Callable[[list[dict[str, object]]], bool]


class DuplicateGroup(BaseModel):
    member_indexes: list[int] = Field(min_length=2)
    representative_index: int
    relationship: Literal["duplicate"]
    reason: str = ""

    model_config = ConfigDict(extra="forbid", frozen=True)


class DeduplicationDecision(BaseModel):
    groups: list[DuplicateGroup]

    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True, slots=True)
class ReviewCandidate:
    group: ReviewGroup
    finding: ReviewFinding


def consolidate_result(
    result: StandardReviewResult,
    *,
    adjudicator: Callable[[list[dict[str, object]]], DeduplicationDecision | None]
    | None,
    packet_fits: PacketFits,
    progress_callback: Callable[[dict[str, object]], None] | None,
    jobs: NodeJobs,
) -> StandardReviewResult:
    original_candidates = [
        ReviewCandidate(group, finding)
        for group in result.reviews
        for finding in group.reviews
    ]
    candidates = _unique_candidates(original_candidates)
    adjudicated = _apply_final_adjudication(
        candidates,
        adjudicator,
        packet_fits=packet_fits,
        progress_callback=progress_callback,
        jobs=jobs,
    )
    kept = adjudicated if adjudicated is not None else candidates
    if len(kept) == len(original_candidates):
        return result

    kept_ids = {id(candidate.finding) for candidate in kept}
    groups: list[ReviewGroup] = []
    for group in result.reviews:
        reviews = [finding for finding in group.reviews if id(finding) in kept_ids]
        if reviews:
            group_data = group.model_dump(mode="python")
            group_data["reviews"] = [item.model_dump(mode="python") for item in reviews]
            groups.append(ReviewGroup.model_validate(group_data))
    return result.model_copy(update={"reviews": groups})


def _unique_candidates(candidates: list[ReviewCandidate]) -> list[ReviewCandidate]:
    unique: list[ReviewCandidate] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        group = candidate.group.model_dump(mode="json", exclude={"reviews"})
        finding = candidate.finding.model_dump(mode="json")
        identity = (
            json.dumps(group, sort_keys=True, separators=(",", ":")),
            json.dumps(finding, sort_keys=True, separators=(",", ":")),
        )
        if identity not in seen:
            seen.add(identity)
            unique.append(candidate)
    return unique


def _apply_final_adjudication(
    candidates: list[ReviewCandidate],
    adjudicator,
    *,
    packet_fits,
    progress_callback=None,
    jobs: NodeJobs,
):
    if not callable(adjudicator) or not candidates:
        return None
    if len(candidates) < 2:
        return candidates

    payloads = [
        _finding_adjudication_payload(index, candidate)
        for index, candidate in enumerate(candidates)
    ]
    original_limit = len(candidates)
    merged = _UnionFind(original_limit)
    representative_preferences = []
    saw_valid_decision = False

    if packet_fits is None:
        return None
    initial_batches = _adjudication_batches(payloads, packet_fits=packet_fits)
    if _run_adjudication_batches(
        initial_batches,
        adjudicator,
        merged,
        representative_preferences,
        original_limit,
        progress_callback=progress_callback,
        phase="candidate",
        jobs=jobs,
    ):
        saw_valid_decision = True

    representative_payloads = [
        payloads[index]
        for index in _representative_indexes(
            merged,
            representative_preferences,
        )
    ]
    if len(representative_payloads) > 1 and not packet_fits(payloads):
        representative_batches = _adjudication_batches(
            representative_payloads,
            packet_fits=packet_fits,
            scope="file",
        )
        if _run_adjudication_batches(
            representative_batches,
            adjudicator,
            merged,
            representative_preferences,
            original_limit,
            progress_callback=progress_callback,
            phase="representative",
            jobs=jobs,
        ):
            saw_valid_decision = True

    if not saw_valid_decision:
        return None

    keep_indexes = set(_representative_indexes(merged, representative_preferences))
    return [
        candidate for index, candidate in enumerate(candidates) if index in keep_indexes
    ]


def _run_adjudication_batches(
    batches,
    adjudicator,
    merged,
    representative_preferences,
    original_limit,
    *,
    progress_callback=None,
    phase="candidate",
    jobs: NodeJobs,
):
    if not batches:
        return False

    total = len(batches)
    if progress_callback:
        progress_callback({"phase": phase, "completed": 0, "total": total})
    batch_results = jobs.run(
        list(enumerate(batches)),
        lambda item: (item[0], adjudicator(item[1])),
        label="Final review deduplication",
        result_key=lambda item: f"{phase}:{item[0]}",
        on_complete=lambda _job, completed, total: (
            progress_callback({"phase": phase, "completed": completed, "total": total})
            if progress_callback
            else None
        ),
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
    packet_fits,
    scope="function",
):
    if len(payloads) < 2:
        return []
    if packet_fits(payloads):
        return [payloads]
    batches = []
    by_scope = defaultdict(list)
    for payload in sorted(payloads, key=_payload_sort_key):
        by_scope[_payload_scope_key(payload, scope)].append(payload)
    for scope_payloads in by_scope.values():
        if len(scope_payloads) < 2:
            continue
        batches.extend(_chunk_payloads(scope_payloads, packet_fits))
    return batches


def _chunk_payloads(payloads, packet_fits):
    chunks = []
    current = []
    for payload in payloads:
        candidate = [*current, payload]
        if current and not packet_fits(candidate):
            if len(current) > 1:
                chunks.append(current)
            current = [payload]
        else:
            current = candidate
    if len(current) > 1 and packet_fits(current):
        chunks.append(current)
    return chunks


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


def _representative_indexes(
    merged: "_UnionFind",
    representative_preferences: list[int],
) -> list[int]:
    representatives = []
    for members in merged.groups().values():
        representative = _preferred_representative(
            members,
            representative_preferences,
        )
        representatives.append(representative)
    return sorted(representatives)


def _preferred_representative(
    members: list[int],
    representative_preferences: list[int],
) -> int:
    member_set = set(members)
    for representative in reversed(representative_preferences):
        if representative in member_set:
            return representative
    return min(members)


def _merge_decision_groups(
    merged,
    representative_preferences,
    decision: DeduplicationDecision | None,
    original_limit,
):
    if decision is None:
        return False
    accepted = False
    for group in decision.groups:
        members = _valid_member_indexes(group.member_indexes, original_limit)
        if len(members) < 2:
            continue
        requested_representative = _representative_index(
            group.representative_index, members
        )
        representative = requested_representative
        if representative is None:
            representative = min(members)
        if requested_representative is not None:
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


def _valid_member_indexes(raw: list[int], limit: int) -> list[int]:
    members = []
    for index in raw:
        if 0 <= index < limit and index not in members:
            members.append(index)
    return members


def _representative_index(index: int, members: list[int]) -> int | None:
    return index if index in members else None


def _finding_adjudication_payload(
    index: int,
    candidate: ReviewCandidate,
) -> dict[str, object]:
    finding = candidate.finding.model_dump(mode="python")
    group = candidate.group.model_dump(mode="python")
    return {
        "index": index,
        "description": str(finding.get("issue") or ""),
        "root_cause": str(finding.get("root_cause") or ""),
        "evidence": str(finding.get("reasoning") or finding.get("evidence") or ""),
        "primary_file": str(
            finding.get("primary_file")
            or group.get("file")
            or group.get("file_path")
            or ""
        ),
        "primary_function": str(finding.get("primary_function") or ""),
        "primary_line": _safe_int(
            finding.get("primary_line") or finding.get("line_number"), 0
        ),
        "analysis_type": str(finding.get("analysis_type") or ""),
        "canonical_key": str(finding.get("canonical_key") or ""),
    }


def _safe_int(value: object, default: int) -> int:
    if not isinstance(value, int | float | str | bytes | bytearray):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
