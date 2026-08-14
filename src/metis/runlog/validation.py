# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .schema import SCHEMA_VERSION

_SPAN_STATUSES = {"ok", "error", "cancelled", "inconclusive"}


class TraceValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TraceSummary:
    run_id: str
    records: int
    spans: int
    events: int
    blobs: int
    status: str


def validate_runlog(path: str | Path, *, verify_blobs: bool = True) -> TraceSummary:
    """Validates one complete v1 run-log bundle and its referenced blobs."""

    trace_path = Path(path).resolve()
    starts: dict[str, dict[str, Any]] = {}
    ended: set[str] = set()
    open_children: dict[str, set[str]] = {}
    record_ids: set[str] = set()
    run_id: str | None = None
    root_span_id: str | None = None
    root_status: str | None = None
    event_count = 0
    blob_refs: dict[str, dict[str, Any]] = {}
    record_count = 0
    last_record: dict[str, Any] | None = None

    with trace_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.endswith("\n"):
                raise TraceValidationError(
                    f"Trace line {line_number} is not newline-terminated"
                )
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TraceValidationError(
                    f"Trace line {line_number} is invalid JSON: {exc}"
                ) from exc
            _require(isinstance(record, dict), line_number, "record object")
            _require(record.get("v") == SCHEMA_VERSION, line_number, "schema version")
            _require(record.get("seq") == record_count, line_number, "sequence")
            _required_string(record, "ts", line_number)
            _require(
                isinstance(record.get("mono_ns"), int)
                and not isinstance(record.get("mono_ns"), bool)
                and record["mono_ns"] >= 0,
                line_number,
                "non-negative mono_ns",
            )
            _required_string(record, "thread", line_number)
            _require(
                isinstance(record.get("thread_id"), int)
                and not isinstance(record.get("thread_id"), bool),
                line_number,
                "integer thread_id",
            )
            _require(
                isinstance(record.get("attributes"), dict),
                line_number,
                "attributes object",
            )
            record_id = _required_string(record, "record_id", line_number)
            _require(record_id not in record_ids, line_number, "unique record_id")
            record_ids.add(record_id)
            current_run_id = _required_string(record, "run_id", line_number)
            if run_id is None:
                run_id = current_run_id
            _require(current_run_id == run_id, line_number, "single run_id")
            _required_string(record, "name", line_number)
            _required_string(record, "explanation", line_number)
            span_id = _required_string(record, "span_id", line_number)
            record_type = record.get("record")
            if record_type == "span.start":
                _require(span_id not in starts, line_number, "unique span start")
                kind = _required_string(record, "kind", line_number)
                _require("status" not in record, line_number, "start status omission")
                _require(
                    "duration_ms" not in record,
                    line_number,
                    "start duration omission",
                )
                _require("error" not in record, line_number, "start error omission")
                parent = record.get("parent_span_id")
                if kind == "run":
                    _require(record_count == 0, line_number, "root span starts first")
                    _require(root_span_id is None, line_number, "single root span")
                    _require(parent is None, line_number, "root parent omission")
                    root_span_id = span_id
                else:
                    _require(root_span_id is not None, line_number, "root span exists")
                    _require(isinstance(parent, str), line_number, "child parent span")
                    _require(parent in starts, line_number, "known parent span")
                    _require(parent not in ended, line_number, "open parent span")
                    open_children[parent].add(span_id)
                starts[span_id] = record
                open_children[span_id] = set()
            elif record_type == "span.end":
                _require(span_id in starts, line_number, "matching span start")
                _require(span_id not in ended, line_number, "single span end")
                _require(
                    not open_children[span_id],
                    line_number,
                    "all child spans ended first",
                )
                start = starts[span_id]
                _require(
                    record.get("parent_span_id") == start.get("parent_span_id"),
                    line_number,
                    "stable parent_span_id",
                )
                _require(
                    record.get("kind") == start.get("kind"), line_number, "stable kind"
                )
                _require(
                    record.get("name") == start.get("name"), line_number, "stable name"
                )
                _require(
                    record.get("explanation") == start.get("explanation"),
                    line_number,
                    "stable explanation",
                )
                status = _required_string(record, "status", line_number)
                _require(status in _SPAN_STATUSES, line_number, "known span status")
                duration = record.get("duration_ms")
                _require(
                    isinstance(duration, (int, float))
                    and not isinstance(duration, bool)
                    and duration >= 0,
                    line_number,
                    "non-negative duration_ms",
                )
                if "error" in record:
                    _require(
                        isinstance(record["error"], dict),
                        line_number,
                        "error object",
                    )
                ended.add(span_id)
                parent = start.get("parent_span_id")
                if isinstance(parent, str):
                    open_children[parent].discard(span_id)
                if span_id == root_span_id:
                    root_status = status
            elif record_type == "event":
                _require(span_id in starts, line_number, "known containing span")
                _require(span_id not in ended, line_number, "open containing span")
                for forbidden in (
                    "parent_span_id",
                    "kind",
                    "status",
                    "duration_ms",
                    "error",
                ):
                    _require(
                        forbidden not in record,
                        line_number,
                        f"event {forbidden} omission",
                    )
                event_count += 1
            else:
                raise TraceValidationError(
                    f"Trace line {line_number} has unknown record type {record_type!r}"
                )
            _collect_blob_refs(record.get("attributes"), blob_refs)
            _collect_blob_refs(record.get("error"), blob_refs)
            record_count += 1
            last_record = record

    if run_id is None or root_span_id is None:
        raise TraceValidationError("Trace has no root span")
    unclosed = set(starts) - ended
    if unclosed:
        raise TraceValidationError(f"Trace has unclosed spans: {sorted(unclosed)!r}")
    if (
        last_record is None
        or last_record.get("record") != "span.end"
        or last_record.get("span_id") != root_span_id
    ):
        raise TraceValidationError("Trace root span must end last")
    meta_status = _validate_meta(trace_path, run_id)
    if root_status != meta_status:
        raise TraceValidationError(
            f"Trace root status {root_status!r} does not match metadata {meta_status!r}"
        )
    if verify_blobs:
        for reference, metadata in blob_refs.items():
            _validate_blob(trace_path.parent, reference, metadata)
    return TraceSummary(
        run_id=run_id,
        records=record_count,
        spans=len(starts),
        events=event_count,
        blobs=len(blob_refs),
        status=meta_status,
    )


def _validate_meta(trace_path: Path, run_id: str) -> str:
    exact_meta = trace_path.with_suffix(trace_path.suffix + ".meta.json")
    bundle_meta = trace_path.parent / "meta.json"
    meta_path = exact_meta if exact_meta.is_file() else bundle_meta
    if not meta_path.is_file():
        raise TraceValidationError(f"Run-log metadata does not exist: {meta_path}")
    try:
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TraceValidationError(f"Run-log metadata is invalid JSON: {exc}") from exc
    _meta_require(isinstance(metadata, dict), "metadata object")
    _meta_require(metadata.get("v") == SCHEMA_VERSION, "metadata schema version")
    _meta_require(metadata.get("run_id") == run_id, "metadata run_id")
    _meta_require(metadata.get("complete") is True, "complete metadata")
    status = metadata.get("status")
    _meta_require(status in _SPAN_STATUSES, "known metadata status")
    _meta_require(metadata.get("content") in {"full", "metadata"}, "content mode")
    _meta_require(isinstance(metadata.get("started_at"), str), "started_at")
    _meta_require(isinstance(metadata.get("ended_at"), str), "ended_at")
    _meta_require(isinstance(metadata.get("metadata"), dict), "metadata payload")
    _meta_require(isinstance(metadata.get("totals"), dict), "metadata totals")
    return str(status)


def _meta_require(condition: bool, invariant: str) -> None:
    if not condition:
        raise TraceValidationError(f"Run-log metadata violates invariant: {invariant}")


def _collect_blob_refs(value: Any, references: dict[str, dict[str, Any]]) -> None:
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str):
            previous = references.setdefault(reference, value)
            if previous.get("sha256") != value.get("sha256"):
                raise TraceValidationError(
                    f"Blob reference {reference!r} has conflicting digests"
                )
            return
        for item in value.values():
            _collect_blob_refs(item, references)
    elif isinstance(value, list):
        for item in value:
            _collect_blob_refs(item, references)


def _validate_blob(base: Path, reference: str, metadata: dict[str, Any]) -> None:
    path = (base / reference).resolve()
    try:
        path.relative_to(base)
    except ValueError as exc:
        raise TraceValidationError(
            f"Blob reference escapes trace directory: {reference}"
        ) from exc
    if not path.is_file():
        raise TraceValidationError(f"Blob reference does not exist: {reference}")
    expected_bytes = metadata.get("bytes")
    if (
        not isinstance(expected_bytes, int)
        or isinstance(expected_bytes, bool)
        or expected_bytes < 0
    ):
        raise TraceValidationError(f"Blob byte count is invalid: {reference}")
    expected_digest = metadata.get("sha256")
    if not isinstance(expected_digest, str) or len(expected_digest) != 64:
        raise TraceValidationError(f"Blob digest is invalid: {reference}")
    try:
        int(expected_digest, 16)
    except ValueError as exc:
        raise TraceValidationError(f"Blob digest is invalid: {reference}") from exc
    if not isinstance(metadata.get("media_type"), str):
        raise TraceValidationError(f"Blob media type is invalid: {reference}")
    if not isinstance(metadata.get("preview"), str):
        raise TraceValidationError(f"Blob preview is invalid: {reference}")
    digest = hashlib.sha256()
    actual_bytes = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            actual_bytes += len(chunk)
            digest.update(chunk)
    if actual_bytes != expected_bytes:
        raise TraceValidationError(f"Blob byte count does not match: {reference}")
    if digest.hexdigest() != expected_digest:
        raise TraceValidationError(f"Blob digest does not match: {reference}")


def _required_string(record: dict[str, Any], key: str, line_number: int) -> str:
    value = record.get(key)
    _require(isinstance(value, str) and bool(value), line_number, key)
    return value


def _require(condition: bool, line_number: int, invariant: str) -> None:
    if not condition:
        raise TraceValidationError(
            f"Trace line {line_number} violates invariant: {invariant}"
        )
