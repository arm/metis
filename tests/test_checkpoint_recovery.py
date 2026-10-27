# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import CancelledError
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Event
from threading import Barrier
from threading import current_thread
import sqlite3
import json

import pytest

from metis.cli import review_checkpoints
from metis.cli import output as cli_output
from metis.cli import utils as cli_utils
from metis.engine.execution import ExecutionDiagnostic
from metis.engine.execution import ExecutionResult
from metis.engine.execution import ExecutionStatus
from metis.engine.stages.review.models import ReviewCheckpointRecord
from metis.engine.stages.review.storage import ReviewOutput
from metis import generated_artifacts
from metis.generated_artifacts import generated_artifact_paths
from metis.version import __version__ as METIS_VERSION


@pytest.mark.parametrize("streaming", [False, True])
def test_generated_artifact_publications_preserve_concurrent_entries(
    tmp_path, streaming
):
    barrier = Barrier(4)

    def publish(index):
        path = tmp_path / f"report-{index}.json"
        if streaming:
            with ReviewOutput(path, [], codebase_path=tmp_path) as output:
                barrier.wait(timeout=5)
                output.publish()
        else:
            barrier.wait(timeout=5)
            cli_utils.save_output(
                path, {"reviews": []}, quiet=True, codebase_path=tmp_path
            )
        return path.resolve()

    with ThreadPoolExecutor(max_workers=4) as executor:
        paths = set(executor.map(publish, range(4)))

    assert generated_artifact_paths(tmp_path) == paths
    assert not list(tmp_path.glob(".metis/tmp-*"))


def test_generated_artifact_publication_waits_for_registry_writer(
    tmp_path, monkeypatch
):
    output = tmp_path / "report.json"
    cli_utils.save_output(output, {"reviews": []}, quiet=True, codebase_path=tmp_path)
    previous = output.read_bytes()
    database = tmp_path / ".metis/generated_artifacts.sqlite3"
    waiting = Event()
    connect = sqlite3.connect

    def trace(statement):
        if statement == "BEGIN IMMEDIATE":
            waiting.set()

    def connect_with_trace(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connection.set_trace_callback(trace)
        return connection

    monkeypatch.setattr(generated_artifacts.sqlite3, "connect", connect_with_trace)
    latest = {"reviews": [], "replacement": True}
    with closing(connect(database)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                cli_utils.save_output,
                output,
                latest,
                quiet=True,
                codebase_path=tmp_path,
            )
            try:
                assert waiting.wait(timeout=5)
                assert output.read_bytes() == previous
            finally:
                connection.commit()
            future.result(timeout=5)

    assert json.loads(output.read_text(encoding="utf-8")) == latest
    assert generated_artifact_paths(tmp_path) == {output}


def test_generated_artifact_registry_timeout_preserves_previous_report(
    tmp_path, monkeypatch
):
    output = tmp_path / "report.json"
    cli_utils.save_output(output, {"reviews": []}, quiet=True, codebase_path=tmp_path)
    previous = output.read_bytes()
    database = tmp_path / ".metis/generated_artifacts.sqlite3"
    connect = sqlite3.connect

    def connect_with_timeout(*args, **kwargs):
        kwargs["timeout"] = 0.01
        return connect(*args, **kwargs)

    monkeypatch.setattr(generated_artifacts.sqlite3, "connect", connect_with_timeout)
    with closing(connect(database)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError, match="database is locked"):
            cli_utils.save_output(
                output,
                {"reviews": [], "replacement": True},
                quiet=True,
                codebase_path=tmp_path,
            )
        connection.rollback()

    assert output.read_bytes() == previous
    assert generated_artifact_paths(tmp_path) == {output}


@pytest.mark.parametrize("external", [False, True])
def test_generated_artifact_publication_tracks_replaced_symlink(tmp_path, external):
    root = tmp_path / "repository"
    root.mkdir()
    source = (tmp_path if external else root) / "source.json"
    source.write_text("original source", encoding="utf-8")
    output = root / "report.json"
    output.symlink_to(source)

    with pytest.raises(TypeError):
        cli_utils.save_output(output, object(), quiet=True, codebase_path=root)

    assert output.is_symlink()
    assert generated_artifact_paths(root) == set()
    cli_utils.save_output(output, {"reviews": []}, quiet=True, codebase_path=root)

    assert not output.is_symlink()
    assert source.read_text(encoding="utf-8") == "original source"
    assert generated_artifact_paths(root) == {output}


def test_generated_artifact_is_recorded_if_cancelled_after_publication(
    tmp_path, monkeypatch
):
    output = tmp_path / "report.json"
    cancelled = CancelledError("cancelled after replacement")

    def cancel(*_args):
        raise cancelled

    monkeypatch.setattr(cli_output, "_record_output_artifact", cancel)
    with pytest.raises(CancelledError) as raised:
        cli_utils.save_output(
            output, {"reviews": []}, quiet=True, codebase_path=tmp_path
        )

    assert raised.value is cancelled
    assert json.loads(output.read_text(encoding="utf-8")) == {"reviews": []}
    assert generated_artifact_paths(tmp_path) == {output}


@pytest.mark.parametrize(
    "failure", ["corrupt", "escaping", "leaf_symlink", "incompatible_schema"]
)
def test_generated_artifact_registry_failure_prevents_replacement(tmp_path, failure):
    root = tmp_path / "repository"
    root.mkdir()
    output = root / "report.json"
    output.write_bytes(b"previous report")
    state = root / ".metis"
    if failure == "escaping":
        state.symlink_to(tmp_path, target_is_directory=True)
    else:
        state.mkdir()
        database = state / "generated_artifacts.sqlite3"
        if failure == "leaf_symlink":
            source = root / "source.sqlite3"
            with closing(sqlite3.connect(source)) as connection:
                connection.execute("CREATE TABLE app_data (value TEXT)")
            source.chmod(0o644)
            before = source.read_bytes()
            database.symlink_to(source)
        elif failure == "incompatible_schema":
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "CREATE TABLE generated_artifacts "
                    "(path TEXT PRIMARY KEY, wrong_signature TEXT NOT NULL)"
                )
            before = database.read_bytes()
        else:
            database.write_bytes(b"invalid database")

    with pytest.raises((OSError, ValueError, sqlite3.DatabaseError)):
        cli_utils.save_output(output, {"reviews": []}, quiet=True, codebase_path=root)

    assert output.read_bytes() == b"previous report"
    if failure == "leaf_symlink":
        assert source.read_bytes() == before
        assert source.stat().st_mode & 0o777 == 0o644
    elif failure == "incompatible_schema":
        assert database.read_bytes() == before


@pytest.mark.parametrize("field", ["json_path", "sarif_path"])
def test_stage_checkpoint_skips_file_references(tmp_path, field):
    report = tmp_path / "report.json"
    report.write_text('{"reviews":[]}')
    checkpoint = review_checkpoints.stage_checkpoint_callback(codebase_path=tmp_path)
    checkpoint(ExecutionResult(ExecutionStatus.OK, {"review": {field: str(report)}}))
    assert not list(tmp_path.glob(".metis/checkpoints/graph.*.json"))
    assert report.read_text() == '{"reviews":[]}'


def test_stage_checkpoint_preserves_previous_snapshot_on_invalid_output(
    tmp_path, caplog
):
    checkpoint = review_checkpoints.stage_checkpoint_callback(codebase_path=tmp_path)
    result = ExecutionResult(
        ExecutionStatus.INCONCLUSIVE,
        {
            "review": {
                "findings": {"reviews": []},
                "private": object(),
                "json_path": "report.json",
                "sarif_path": "report.sarif",
            }
        },
        (ExecutionDiagnostic("review.file_failed", "Failed file"),),
    )
    checkpoint(result)
    path = next(tmp_path.glob(".metis/checkpoints/graph.*.json"))
    before = path.read_bytes()
    payload = json.loads(before)
    assert payload["status"] == "inconclusive"
    assert payload["diagnostics"][0]["code"] == "review.file_failed"
    assert payload["outputs"]["review"] == {"findings": {"reviews": []}}

    checkpoint(
        ExecutionResult(ExecutionStatus.OK, {"review": {"findings": float("nan")}})
    )

    assert path.read_bytes() == before
    assert "Unable to save stage checkpoint" in caplog.text


def test_stage_checkpoint_does_not_follow_escaping_state_directory(tmp_path, caplog):
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (repository / ".metis").symlink_to(outside, target_is_directory=True)
    checkpoint = review_checkpoints.stage_checkpoint_callback(codebase_path=repository)

    checkpoint(ExecutionResult(ExecutionStatus.OK, {"review": {"findings": {}}}))

    assert not list(outside.iterdir())
    assert "Unable to save stage checkpoint" in caplog.text


@pytest.mark.parametrize("external", [False, True])
@pytest.mark.parametrize(
    "link_path",
    [".metis", ".metis/checkpoints", ".metis/checkpoints/review.fixture.sqlite3"],
)
def test_review_checkpoint_paths_are_checked_at_each_access(
    tmp_path, caplog, external, link_path
):
    repository = tmp_path / "repository"
    repository.mkdir()
    callbacks = review_checkpoints.review_checkpoint_callbacks(
        codebase_path=repository, enabled=True
    )
    destination = (tmp_path if external else repository) / "relocated"
    filename = "review.fixture.sqlite3"
    leaf_link = link_path.endswith(".sqlite3")
    if leaf_link:
        destination /= filename
        stored = destination
    else:
        stored = destination / (
            f"checkpoints/{filename}" if link_path == ".metis" else filename
        )
    record = ReviewCheckpointRecord(
        metis_version=METIS_VERSION,
        producer="fixture",
        key="original",
        record={"reviews": []},
    )
    review_checkpoints._write_sqlite_record(stored, record)
    before = stored.read_bytes()
    link = repository / link_path
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(destination, target_is_directory=not leaf_link)

    resumed = callbacks["review_resume_callback"]("fixture")
    callbacks["review_checkpoint_callback"](
        record.model_copy(update={"key": "new"}).model_dump(mode="json"), 1, 1
    )

    if external or leaf_link:
        assert resumed is None
        assert stored.read_bytes() == before
        assert "Unable to save review checkpoint" in caplog.text
    else:
        assert resumed == {"original": {"reviews": []}}
        assert callbacks["review_resume_callback"]("fixture") == {
            "original": {"reviews": []},
            "new": {"reviews": []},
        }


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
    malformed = '{"nested":' + "[" * 10000
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            "INSERT INTO review_checkpoint_records VALUES (?, ?, ?)",
            (METIS_VERSION, "m_invalid", malformed),
        )

    assert review_checkpoints._sqlite_records(path) == {
        "a_valid": {"revision": 1},
        "z_valid": {"revision": 1},
    }
