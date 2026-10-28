# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from threading import RLock
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from itertools import chain
from itertools import groupby

from metis.generated_artifacts import generated_artifact_publication
from metis.json_io import JsonArray
from metis.json_io import JsonJournal
from metis.json_io import sorted_json_records
from metis.json_io import JsonSnapshot
from metis.json_io import write_json_stream_atomic
from metis.sarif.triage import SarifFinding
from metis.sarif.triage import TRIAGE_ANNOTATION_KEYS
from metis.sarif.triage import _apply_triage_properties
from metis.sarif.triage import _is_already_triaged
from metis.sarif.triage import _run_source_metadata
from metis.sarif.triage import _to_finding
from metis.sarif.writer import generate_sarif
from metis.sarif.writer import iter_sarif_results
from metis.sarif.writer import normalize_finding_ids


class _ReviewFinding(SarifFinding):
    __slots__ = ("_source_position", "_finding")

    def __init__(self, finding: SarifFinding, source_position: tuple[int, int]):
        super().__init__(**vars(finding))
        self._source_position = source_position
        self._finding = finding


def is_sarif_file(snapshot: JsonSnapshot) -> bool:
    """Distinguish SARIF from Metis review JSON without materializing either."""
    has_runs = False
    with closing(snapshot.events()) as events:
        for path, event, _value in events:
            if path == ("reviews",) and event == "start_array":
                return False
            if path == ("runs",) and event == "start_array":
                has_runs = True
    return has_runs


class TriageStore:
    """Sequential JSON snapshot, group metadata, and ordered decision log."""

    def __init__(
        self,
        source: str | Path,
        *,
        destination: str | Path | None = None,
        codebase_path: str | Path | None = None,
    ) -> None:
        if destination is not None:
            Path(destination).parent.mkdir(parents=True, exist_ok=True)
        self._json = None
        self._updates = None
        self._codebase_path = codebase_path
        try:
            self._json = JsonSnapshot(source)
            self.directory = self._json.directory
            self.is_review = Path(
                source
            ).suffix.lower() != ".sarif" and not is_sarif_file(self._json)
            self._root = "reviews" if self.is_review else "runs"
            self._collection = "reviews" if self.is_review else "results"
            self._record_path = (self._root, None, self._collection, None)
            self._metadata = self.directory / "groups.jsonl"
            self._decisions = self.directory / "decisions.jsonl"
            self._lock = RLock()
            self._publication_lock = RLock()
            self.processed = self._total = self._remaining = 0
            self._validate()
            if self.is_review:
                self._normalize_review()
            self._updates = JsonJournal(self._decisions)
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> TriageStore:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def close(self) -> None:
        try:
            if self._updates is not None:
                self._updates.close()
        finally:
            if self._json is not None:
                self._json.close()

    def _validate(self) -> None:
        has_array = False
        version = None
        metadata = {}
        group_count = 0
        fields = ("file", "file_path") if self.is_review else ("name", "fullName")
        field_prefix = (
            (self._root, None)
            if self.is_review
            else (self._root, None, "tool", "driver")
        )

        with self._metadata.open("w", encoding="utf-8") as groups:

            def observe(path, event, value):
                nonlocal has_array, version, metadata, group_count
                if event in {"map_key", "end_array"}:
                    return
                if path == ("version",):
                    version = value
                if path == (self._root,):
                    if event != "start_array":
                        raise ValueError(f"Triage {self._root} must be an array")
                    has_array = True
                if len(path) == 2 and path[0] == self._root:
                    if event == "start_map":
                        metadata = {}
                        group_count = 0
                    elif event == "end_map":
                        if self.is_review and group_count:
                            self._sarif_result(
                                (self._root, path[1], self._collection, 0), {}, metadata
                            )
                        groups.write(
                            json.dumps(
                                [path[1], metadata, group_count],
                                ensure_ascii=True,
                                allow_nan=False,
                            )
                            + "\n"
                        )
                    else:
                        raise ValueError("Triage groups must be objects")
                if (
                    len(path) == 3
                    and path[0] == self._root
                    and path[2] == self._collection
                    and event != "start_array"
                ):
                    raise ValueError(
                        "Triage findings must be an array"
                        if self.is_review
                        else f"SARIF run {path[1]} results must be an array"
                    )

            for path, value in self._json.items(
                self._record_path,
                *(field_prefix + (field,) for field in fields),
                observe=observe,
            ):
                if len(path) == 4 and path[2] == self._collection:
                    if not isinstance(value, dict):
                        raise ValueError(
                            "Triage findings must be objects"
                            if self.is_review
                            else f"SARIF result {path[1]}:{path[3]} must be an object"
                        )
                    self._total += 1
                    group_count += 1
                    self._remaining += not _is_already_triaged(
                        value if self.is_review else value.get("properties")
                    )
                    if self.is_review:
                        self._sarif_result(path, value, {})
                else:
                    metadata[path[-1]] = value
        if not has_array or not self.is_review and version != "2.1.0":
            raise ValueError(
                "Input must contain a Metis reviews array or a SARIF 2.1.0 runs array"
            )

    def count(self, *, include_triaged: bool = False) -> int:
        return self._total if include_triaged else self._remaining

    @staticmethod
    def public_finding(finding: SarifFinding) -> SarifFinding:
        return finding._finding if isinstance(finding, _ReviewFinding) else finding

    def _records(self):
        current_group = -1
        metadata = {}
        with (
            self._json._reader(self._metadata, text=True) as groups,
            closing(self._json.items(self._record_path)) as records,
        ):
            for path, result in records:
                while current_group < path[1]:
                    current_group, metadata, _count = json.loads(next(groups))
                yield path, result, metadata

    def findings(self, *, include_triaged: bool = False) -> Iterator[SarifFinding]:
        with closing(self._records()) as records:
            for result_index, (path, result, metadata) in enumerate(records):
                if not include_triaged and _is_already_triaged(
                    result if self.is_review else result.get("properties")
                ):
                    continue
                if self.is_review:
                    result = self._sarif_result(path, result, metadata)
                    source_tool, is_metis = "Metis", True
                else:
                    source_tool, is_metis = _run_source_metadata(
                        {"tool": {"driver": metadata}}
                    )
                finding = _to_finding(
                    0 if self.is_review else path[1],
                    result_index if self.is_review else path[3],
                    result,
                    source_tool=source_tool,
                    is_metis_source=is_metis,
                )
                if self.is_review:
                    finding = _ReviewFinding(finding, (path[1], path[3]))
                del result
                yield finding

    def annotate(self, finding: SarifFinding, properties: dict) -> None:
        key = (
            finding._source_position
            if isinstance(finding, _ReviewFinding)
            else (finding.run_index, finding.result_index)
        )
        with self._lock:
            self._updates.append({"position": list(key), "properties": properties})
            self.processed += 1

    def _changes(self):
        with (
            sorted_json_records(
                JsonJournal.records(
                    self._decisions,
                    limit=self._updates.flush(),
                ),
                key=lambda record: record["position"],
                directory=self.directory,
            ) as changes,
            self._metadata.open(encoding="utf-8") as groups,
        ):
            group_index, count = -1, 0
            previous = (-1, -1)
            for record in changes:
                position = record.get("position")
                if (
                    not isinstance(position, list)
                    or len(position) != 2
                    or any(type(value) is not int or value < 0 for value in position)
                ):
                    raise ValueError("Invalid triage journal position")
                while group_index < position[0]:
                    line = next(groups, None)
                    if line is None:
                        raise ValueError("Triage journal group is out of range")
                    group_index, _metadata, count = json.loads(line)
                key = tuple(position)
                if (
                    key <= previous
                    or position[1] >= count
                    or not isinstance(record.get("properties"), dict)
                ):
                    raise ValueError("Invalid triage journal record")
                previous = key
                if set(record["properties"]) - TRIAGE_ANNOTATION_KEYS:
                    raise ValueError("Unknown triage annotation in journal")
                _is_already_triaged(record["properties"])
                yield key, record["properties"]

    def _normalize_review(self):
        def identities():
            for path, issue in self._json.items(self._record_path):
                yield {
                    "id": str(issue.get("id") or "").strip(),
                    "position": [path[1], path[3]],
                }

        with normalize_finding_ids(
            identities(),
            directory=self.directory,
        ) as ordered:

            def normalize(path, issue):
                record = next(ordered)
                issue["id"] = record["id"]
                _apply_triage_properties(issue, issue)
                return issue

            self._json.write(self._json.path, at=self._record_path, transform=normalize)

    @staticmethod
    def _sarif_result(path, issue, metadata):
        group = {
            **metadata,
            "reviews": [
                {**issue, "id": issue.get("id") or f"json:{path[1]}:{path[3]}"}
            ],
        }
        return next(iter_sarif_results([group], read_source=False))

    def publish(
        self,
        target: str | Path,
        *,
        read_source: bool = False,
        observe=None,
    ) -> None:
        with self._publication_lock:
            publication = generated_artifact_publication(self._codebase_path, target)
            with closing(self._changes()) as changes:
                current = next(changes, None)

                def annotate(path, result):
                    nonlocal current
                    if current is not None and current[0] == (path[1], path[3]):
                        properties = (
                            result if self.is_review else result.get("properties")
                        )
                        if not isinstance(properties, dict):
                            properties = {}
                        for key in TRIAGE_ANNOTATION_KEYS:
                            properties.pop(key, None)
                        properties.update(current[1])
                        if not self.is_review:
                            result["properties"] = properties
                        current = next(changes, None)
                    if observe is not None:
                        observe(path, result)
                    return result

                if self.is_review and Path(target).suffix.lower() == ".sarif":
                    with closing(self._records()) as records:

                        def groups():
                            for _group, entries in groupby(
                                records, key=lambda item: item[0][1]
                            ):
                                first = next(entries)
                                yield {
                                    **first[2],
                                    "reviews": (
                                        annotate(path, result)
                                        for path, result, _metadata in chain(
                                            (first,), entries
                                        )
                                    ),
                                }

                        report = generate_sarif({"reviews": []}, read_source=False)
                        report["runs"][0]["results"] = JsonArray(
                            iter_sarif_results(
                                groups(), read_source=read_source, normalize_ids=False
                            )
                        )
                        write_json_stream_atomic(
                            target,
                            report,
                            publication=publication,
                        )
                else:
                    self._json.write(
                        target,
                        at=self._record_path,
                        transform=annotate,
                        publication=publication,
                    )
