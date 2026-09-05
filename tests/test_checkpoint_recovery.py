# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Event
from threading import current_thread
import sqlite3

import pytest

from metis.cli import review_checkpoints
from metis.engine.stages.review.models import ReviewCheckpointRecord
from metis.version import __version__ as METIS_VERSION


@pytest.mark.parametrize(
    "contents", [b"inert invalid sqlite", b"SQLite format 3\x00" + bytes(256)]
)
def test_corrupt_checkpoints_are_preserved_after_reads_and_writes(
    tmp_path, caplog, contents
):
    path = tmp_path / "checkpoint.sqlite3"
    path.write_bytes(contents)
    record = ReviewCheckpointRecord(
        metis_version=METIS_VERSION,
        producer="fixture",
        key="one",
        record={"revision": 1},
    )

    assert review_checkpoints._sqlite_records(path) is None
    review_checkpoints._write_sqlite_record(path, record)

    assert path.read_bytes() == contents
    assert "Unable to save review checkpoint" in caplog.text


def test_incompatible_checkpoint_schema_is_preserved(tmp_path, caplog):
    path = tmp_path / "checkpoint.sqlite3"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE review_checkpoint_records (custom TEXT)")
        connection.execute("INSERT INTO review_checkpoint_records VALUES ('retained')")
    before = path.read_bytes()
    record = ReviewCheckpointRecord(
        metis_version=METIS_VERSION, producer="fixture", key="one", record={}
    )

    assert review_checkpoints._sqlite_records(path) is None
    review_checkpoints._write_sqlite_record(path, record)

    assert path.read_bytes() == before
    assert "Unable to save review checkpoint" in caplog.text


@pytest.mark.parametrize("reading", [False, True])
def test_stale_corruption_error_preserves_another_writers_replacement(
    tmp_path, monkeypatch, reading
):
    path = tmp_path / "checkpoint.sqlite3"
    path.write_bytes(b"inert invalid sqlite")
    observed, replacement_done = Event(), Event()
    original_connect = review_checkpoints._connect_checkpoint
    record = ReviewCheckpointRecord(
        metis_version=METIS_VERSION,
        producer="fixture",
        key="completed",
        record={"revision": 1},
    )

    class Connection:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def execute(self, *args, **kwargs):
            try:
                return self.connection.execute(*args, **kwargs)
            except sqlite3.DatabaseError:
                # Pause an actual SQLite error until another writer publishes a
                # healthy replacement. The error still describes the old file.
                observed.set()
                assert replacement_done.wait(5)
                raise

    def connect(target):
        connection = original_connect(target)
        if current_thread().name.startswith("stale-checkpoint"):
            return Connection(connection)
        return connection

    monkeypatch.setattr(review_checkpoints, "_connect_checkpoint", connect)

    def stale_operation():
        if reading:
            review_checkpoints._sqlite_records(path)
        else:
            review_checkpoints._write_sqlite_record(
                path, record.model_copy(update={"key": "stale"})
            )

    def replace_checkpoint():
        try:
            assert observed.wait(5)
            replacement = tmp_path / "replacement.sqlite3"
            review_checkpoints._write_sqlite_record(replacement, record)
            replacement.replace(path)
        finally:
            replacement_done.set()

    with ThreadPoolExecutor(
        max_workers=1, thread_name_prefix="stale-checkpoint"
    ) as stale:
        with ThreadPoolExecutor(max_workers=1) as replacement:
            pending = stale.submit(stale_operation)
            replacement.submit(replace_checkpoint).result(timeout=10)
            pending.result(timeout=10)

    assert review_checkpoints._sqlite_records(path) == {"completed": {"revision": 1}}


def test_undecodable_nested_checkpoint_does_not_hide_other_records(tmp_path):
    path = tmp_path / "checkpoint.sqlite3"
    record = ReviewCheckpointRecord(
        metis_version=METIS_VERSION,
        producer="fixture",
        key="a_valid",
        record={"revision": 1},
    )
    review_checkpoints._write_sqlite_record(path, record)
    review_checkpoints._write_sqlite_record(
        path, record.model_copy(update={"key": "z_valid"})
    )
    malformed = '{"nested":' + "[" * 10000 + "0" + "]" * 10000 + "}"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            "INSERT INTO review_checkpoint_records VALUES (?, ?, ?)",
            (METIS_VERSION, "m_invalid", malformed),
        )

    assert review_checkpoints._sqlite_records(path) == {
        "a_valid": {"revision": 1},
        "z_valid": {"revision": 1},
    }
