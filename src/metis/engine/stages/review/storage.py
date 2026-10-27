# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from itertools import chain
from itertools import groupby
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import RLock
from uuid import uuid4

from metis.generated_artifacts import generated_artifact_publication
from metis.json_io import JsonArray
from metis.json_io import JsonJournal
from metis.json_io import write_json_stream_atomic
from metis.sarif.writer import generate_sarif
from metis.sarif.writer import iter_sarif_results
from metis.sarif.writer import normalize_finding_ids

from .models import ReviewGroup


class ReviewOutput:
    def __init__(
        self,
        target,
        files,
        *,
        mode="code",
        codebase_path=None,
    ):
        self.target = Path(target)
        self._codebase_path = codebase_path
        self.metadata = {"overall_changes": ""} if mode == "patch" else {}
        self._id_namespace = uuid4()
        self._publication_lock = RLock()
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self._directory = TemporaryDirectory(prefix="metis-stream-")
        self._summaries = None
        self._journal = None
        try:
            self.directory = Path(self._directory.name)
            self.path = self.directory / "records.jsonl"
            self._summaries = (
                JsonJournal(self.directory / "summaries.jsonl")
                if mode == "patch"
                else None
            )
            self._journal = JsonJournal(self.path)
            self._lock = RLock()
            self._order = {
                str(Path(path).absolute()): index for index, path in enumerate(files)
            }
            self._parts = {}
            self._starts = {}
            self.count = 0
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        try:
            if self._journal is not None:
                self._journal.close()
        finally:
            try:
                if self._summaries is not None:
                    self._summaries.close()
            finally:
                self._directory.cleanup()

    def begin_patch_entry(self, entry_index, file_path):
        file_path = str(Path(file_path).absolute())
        with self._lock:
            self._order[file_path] = entry_index
            self._starts[file_path] = self._journal.size

    def append(self, group):
        group = ReviewGroup.model_validate(group).model_dump(mode="json")
        file_path = str(
            Path(group.get("file_path") or group.get("file") or "").absolute()
        )
        with self._lock:
            order = self._order.setdefault(file_path, len(self._order))
            part = self._parts.get(order, 0)
            self._starts.setdefault(file_path, self._journal.size)
            self._journal.append({"order": order, "part": part, "group": group})
            self._parts[order] = part + 1
            self.count += len(group["reviews"])

    @staticmethod
    def records(path, *, limit=None):
        for record in JsonJournal.records(path, limit=limit):
            if any(
                type(record.get(key)) is not int or record[key] < 0
                for key in ("order", "part")
            ):
                raise ValueError("Invalid review journal position")
            group = ReviewGroup.model_validate(record["group"])
            metadata = group.model_dump(mode="json", exclude={"reviews"})
            if not group.reviews:
                yield {
                    "position": [record["order"], record["part"], -1],
                    "group": metadata,
                    "finding": None,
                    "id": None,
                }
            for index, finding in enumerate(group.reviews):
                yield {
                    "position": [record["order"], record["part"], index],
                    "group": metadata,
                    "finding": finding.model_dump(mode="json"),
                    "id": finding.id,
                }

    def flush(self):
        return self._journal.flush()

    def publish(self, records=None, *, check_cancelled=lambda: None):
        check_cancelled()
        limit = self.flush()
        summary_limit = self._summaries.flush() if self._summaries is not None else 0
        with self._publication_lock:
            metadata = self.metadata
            if self._summaries is not None:

                def summaries():
                    for record in JsonJournal.records(
                        self._summaries.path, limit=summary_limit
                    ):
                        check_cancelled()
                        if set(record) != {"summary"} or not isinstance(
                            record["summary"], str
                        ):
                            raise ValueError("Invalid review journal summary")
                        if record["summary"]:
                            yield record["summary"]

                metadata = {**metadata, "overall_changes": "\n\n".join(summaries())}
            written = 0
            sarif = self.target.suffix.lower() == ".sarif"
            with normalize_finding_ids(
                self.records(self.path, limit=limit) if records is None else records,
                directory=self.directory,
                check_cancelled=check_cancelled,
                id_namespace=self._id_namespace,
            ) as ordered:

                def groups():
                    for _order, entries in groupby(
                        ordered, key=lambda record: record["position"][0]
                    ):
                        first = next(entries)

                        def findings():
                            nonlocal written
                            for record in chain((first,), entries):
                                if record["group"] != first["group"]:
                                    raise ValueError(
                                        "Inconsistent review journal records"
                                    )
                                if record["finding"] is not None:
                                    written += 1
                                    yield {**record["finding"], "id": record["id"]}

                        yield {
                            "reviews": findings() if sarif else JsonArray(findings()),
                            **first["group"],
                        }

                if sarif:
                    payload = generate_sarif({"reviews": []})
                    payload["runs"][0]["results"] = JsonArray(
                        iter_sarif_results(groups(), normalize_ids=False)
                    )
                else:
                    payload = {"reviews": JsonArray(groups()), **metadata}
                write_json_stream_atomic(
                    self.target,
                    payload,
                    publication=generated_artifact_publication(
                        self._codebase_path, self.target
                    ),
                )
            check_cancelled()
            return written

    def add_summary(self, summary):
        if self._summaries is None or not isinstance(summary, str):
            raise ValueError("Invalid patch review summary")
        with self._lock:
            self._summaries.append({"summary": summary})

    def issues(self, file_path):
        file_path = str(Path(file_path).absolute())
        with self._lock:
            start = self._starts.get(file_path, self._journal.size)
        limit = self._journal.flush()
        for record in JsonJournal.records(self.path, start=start, limit=limit):
            if record["group"]["file_path"] == file_path:
                for finding in record["group"]["reviews"]:
                    yield finding["issue"]
