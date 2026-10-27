# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import json
from collections import defaultdict
from contextlib import closing
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import batched
from itertools import groupby
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from metis.engine.concurrency import _cancellation_checkpoint
from metis.engine.stages.review.models import ReviewFinding
from metis.engine.stages.review.models import ReviewGroup
from metis.utils import safe_int
from metis.json_io import JsonJournal
from metis.json_io import sorted_json_records


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


def _identity(record):
    return json.dumps(
        [
            record["group"],
            {key: value for key, value in record["finding"].items() if key != "id"},
        ],
        sort_keys=True,
        separators=(",", ":"),
    )


@contextmanager
def consolidate_records(
    records,
    *,
    directory,
    adjudicator,
    packet_fits,
    jobs,
    workers,
    progress_callback=None,
):
    def unique_records():
        with sorted_json_records(
            records,
            key=lambda record: (_identity(record), record["position"]),
            directory=directory,
            check_cancelled=_cancellation_checkpoint,
        ) as ordered:
            previous = None
            for record in ordered:
                identity = _identity(record)
                if identity != previous:
                    yield record
                    previous = identity

    current = directory / "candidates.jsonl"
    with (
        sorted_json_records(
            unique_records(),
            key=lambda record: record["position"],
            directory=directory,
            check_cancelled=_cancellation_checkpoint,
        ) as ordered,
        JsonJournal(current) as candidates,
    ):
        for index, record in enumerate(ordered):
            candidates.append({**record, "index": index})

    if candidates.count < 2 or not callable(adjudicator) or packet_fits is None:
        with closing(JsonJournal.records(current)) as kept:
            yield kept
        return

    def payload(record):
        return _finding_adjudication_payload(
            record["index"],
            ReviewCandidate(
                ReviewGroup.model_validate(record["group"]),
                ReviewFinding.model_validate(record["finding"]),
            ),
        )

    def keep(batches, phase):
        def decide(batch):
            if len(batch) < 2:
                return batch
            descriptions = [payload(record) for record in batch]
            if not packet_fits(descriptions):
                return batch
            indexes = {record["index"] for record in batch}
            merged = _UnionFind(indexes)
            preferences = []
            _merge_decision_groups(
                merged, preferences, adjudicator(descriptions), indexes
            )
            representatives = set(_representative_indexes(merged, preferences))
            return [record for record in batch if record["index"] in representatives]

        completed = 0
        if progress_callback:
            progress_callback({"phase": phase, "completed": completed})
        for window in batched(batches, workers):
            for survivors in jobs.run(
                window,
                decide,
                label=None,
                result_key=lambda batch: tuple(batch[0]["position"]),
            ):
                completed += 1
                if progress_callback:
                    progress_callback({"phase": phase, "completed": completed})
                yield from survivors
        if progress_callback:
            progress_callback(
                {"phase": phase, "completed": completed, "total": completed}
            )

    def whole_packet(entries):
        batch = []
        descriptions = []
        next_check = 1
        for record in entries:
            _cancellation_checkpoint()
            batch.append(record)
            descriptions.append(payload(record))
            if len(batch) == next_check:
                if not packet_fits(descriptions):
                    return None
                next_check *= 2
        if descriptions and not packet_fits(descriptions):
            return None
        return batch

    for scope, phase in (("function", "candidate"), ("file", "representative")):
        with (
            closing(JsonJournal.records(current))
            if scope == "function"
            else sorted_json_records(
                JsonJournal.records(current),
                key=lambda record: record["index"],
                directory=directory,
                check_cancelled=_cancellation_checkpoint,
            )
        ) as ordered:
            batch = whole_packet(ordered)
        if batch is not None:
            kept = list(keep((batch,), phase))
            yield (record for record in kept)
            return
        output_path = directory / f"dedup-{scope}.jsonl"
        with (
            sorted_json_records(
                JsonJournal.records(current),
                key=lambda record: _payload_sort_key(payload(record)),
                directory=directory,
                check_cancelled=_cancellation_checkpoint,
            ) as ordered,
            JsonJournal(output_path) as output,
        ):

            def batches():
                for _scope, entries in groupby(
                    ordered,
                    key=lambda record: _payload_scope_key(payload(record), scope),
                ):
                    batch = []
                    descriptions = []
                    for record in entries:
                        _cancellation_checkpoint()
                        description = payload(record)
                        proposed_descriptions = [*descriptions, description]
                        if batch and not packet_fits(proposed_descriptions):
                            yield batch
                            batch = [record]
                            descriptions = [description]
                        else:
                            batch.append(record)
                            descriptions = proposed_descriptions
                    if batch:
                        yield batch

            for record in keep(batches(), phase):
                output.append(record)
        current = output_path
    with closing(JsonJournal.records(current)) as kept:
        yield kept


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
    batch_indexes: set[int],
):
    if decision is None:
        return
    for group in decision.groups:
        members = list(dict.fromkeys(group.member_indexes))
        representative = group.representative_index
        if (
            len(members) < 2
            or any(member not in batch_indexes for member in members)
            or representative not in members
        ):
            continue
        representative_preferences.append(representative)
        for member in members:
            merged.union(representative, member)


class _UnionFind:
    def __init__(self, indexes):
        self._parent = {index: index for index in indexes}

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
        for index in self._parent:
            grouped[self.find(index)].append(index)
        return grouped


def _finding_adjudication_payload(
    index: int,
    candidate: ReviewCandidate,
) -> dict[str, object]:
    finding = candidate.finding.model_dump(mode="python")
    group = candidate.group.model_dump(mode="python", exclude={"reviews"})
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
    return safe_int(value, default)
