# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Exercise persistence across real connections and independently created services."""

from concurrent.futures import CancelledError
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
from threading import Barrier
from threading import Event
from threading import RLock
from threading import Thread
from types import SimpleNamespace

from langgraph.store.memory import InMemoryStore
import pytest

from metis.cli import review_checkpoints
from metis.cli.review_checkpoints import review_checkpoint_callbacks
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import CodeGraphReference
from metis.engine.codegraph import CodeGraphResult
from metis.engine.codegraph import FunctionNode
from metis.engine.execution.contracts import NodeCallbacks
from metis.engine.nodes.codegraph import CodeGraphService
from metis.engine.nodes.codegraph import store as graph_store
from metis.engine.nodes.codegraph.store import SQLiteCodeGraphStore
from metis.engine.repository import EngineRepository
from metis.engine.runtime import EngineState
from metis.engine.stages.review.checkpoints import ReviewCheckpointSession
from metis.memory import MemoryRecord
from metis.memory import MemoryService
from metis.memory import SQLiteMemoryStore
from metis.memory import service as memory_service
from metis.plugins.registry import LanguagePluginRegistry
from metis.version import __version__ as METIS_VERSION


class _ObservedLock:
    def __init__(self, lock):
        self._lock = lock
        self.contended = Event()

    def __enter__(self):
        if not self._lock.acquire(blocking=False):
            self.contended.set()
            assert self._lock.acquire(timeout=5)
        return self

    def __exit__(self, *_args):
        self._lock.release()


def _checkpoint_callbacks(root):
    callbacks = review_checkpoint_callbacks(codebase_path=root, enabled=True)
    return NodeCallbacks(
        checkpoint=callbacks["review_checkpoint_callback"],
        resume=callbacks["review_resume_callback"],
    )


def _memory_record(key, namespace=("repo", "notes")):
    return MemoryRecord.create(
        namespace=namespace,
        key=key,
        tool_version=METIS_VERSION,
        artifact_type="note",
        repo_fingerprint="repository",
        input_fingerprint="input",
        memory_type="semantic",
        summary_text=key,
        search_text=key,
        metadata={"authority": "documented"},
    )


def _graph_service(root, factory):
    registry = LanguagePluginRegistry(
        [
            {
                "name": "fixture",
                "config_resource": "languages/python.yaml",
                "extensions": [".fixture"],
                "capabilities": {"codegraph": True},
            }
        ]
    )
    config = SimpleNamespace(
        codebase_path=str(root),
        language_registry=registry,
        metisignore_file=None,
        review_code_include_paths=[],
        review_code_exclude_paths=[],
    )
    return CodeGraphService(
        config, EngineRepository(config, EngineState()), {"fixture": factory}
    )


def _save_graph(
    store, *, failed=(), fingerprint="stable-input", producer_version=METIS_VERSION
):
    graph = CodeGraph()
    graph.add_node(FunctionNode("module.fixture::entry", "module.fixture", "entry", 1))
    return store.save(
        fingerprint=fingerprint,
        producer_version=producer_version,
        graph=graph,
        processed_files=("module.fixture",),
        failed_files=failed,
        diagnostics=(),
    )


def test_checkpoint_session_round_trip_keeps_concurrent_updates_ordered(tmp_path):
    callbacks = _checkpoint_callbacks(tmp_path)
    first_started, release_first, second_started = Event(), Event(), Event()
    observed = []
    session = None

    def persist(payload, processed, total):
        # Observers may inspect the session without acquiring the write-order lock.
        observed.append(session.get(payload["key"]))
        if payload["record"]["revision"] == 1:
            first_started.set()
            assert release_first.wait(5)
        else:
            second_started.set()
        callbacks.checkpoint(payload, processed, total)

    session = ReviewCheckpointSession("fixture", NodeCallbacks(checkpoint=persist))
    write_lock = _ObservedLock(session._write_lock)
    session._write_lock = write_lock
    first = Thread(target=session.put, args=("same-key", {"revision": 1}), daemon=True)
    second = Thread(target=session.put, args=("same-key", {"revision": 2}), daemon=True)
    first.start()
    try:
        assert first_started.wait(5)
        second.start()
        assert write_lock.contended.wait(5)
        assert not second_started.is_set()
    finally:
        release_first.set()
        first.join(timeout=5)
        if second.ident is not None:
            second.join(timeout=5)
    assert not first.is_alive() and not second.is_alive()

    reopened = ReviewCheckpointSession("fixture", _checkpoint_callbacks(tmp_path))
    assert observed == [{"revision": 1}, {"revision": 2}]
    assert reopened.has_records
    assert reopened.get("same-key") == session.get("same-key") == {"revision": 2}
    reopened.put("other-key", {"revision": 3})
    restarted = ReviewCheckpointSession("fixture", _checkpoint_callbacks(tmp_path))
    assert restarted.get("same-key") == {"revision": 2}
    assert restarted.get("other-key") == {"revision": 3}


@pytest.mark.parametrize("failure_type", [None, RuntimeError, CancelledError])
def test_checkpoint_session_defers_reentrant_writes_and_preserves_failures(
    tmp_path, failure_type
):
    callbacks = _checkpoint_callbacks(tmp_path)
    failure = failure_type("inert checkpoint failure") if failure_type else None
    attempts, errors = [], []
    session = None

    def persist(payload, processed, total):
        revision = payload["record"]["revision"]
        attempts.append(revision)
        if revision == 1:
            session.put("key", {"revision": 2})
            if failure is not None:
                raise failure
        callbacks.checkpoint(payload, processed, total)

    session = ReviewCheckpointSession("fixture", NodeCallbacks(checkpoint=persist))

    def write():
        try:
            session.put("key", {"revision": 1})
        except BaseException as exc:
            errors.append(exc)

    worker = Thread(target=write, daemon=True)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert session.get("key") == {"revision": 2}
    reopened = ReviewCheckpointSession("fixture", _checkpoint_callbacks(tmp_path))
    if failure_type is CancelledError:
        assert errors == [failure]
        assert attempts == [1]
        assert reopened.get("key") is None
    else:
        assert errors == []
        assert attempts == [1, 2]
        assert reopened.get("key") == {"revision": 2}

    session.put("key", {"revision": 3})
    assert attempts == ([1, 3] if failure_type is CancelledError else [1, 2, 3])
    assert ReviewCheckpointSession("fixture", _checkpoint_callbacks(tmp_path)).get(
        "key"
    ) == {"revision": 3}


def test_legacy_checkpoint_resume_isolates_producer_and_version(tmp_path):
    path = tmp_path / ".metis/checkpoints/review.alpha.sqlite3"
    path.parent.mkdir(parents=True)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            "CREATE TABLE review_checkpoint_records (producer TEXT NOT NULL, "
            "metis_version TEXT NOT NULL, record_key TEXT NOT NULL, payload TEXT NOT NULL, "
            "PRIMARY KEY(producer, metis_version, record_key)) WITHOUT ROWID"
        )
        connection.executemany(
            "INSERT INTO review_checkpoint_records VALUES (?, ?, ?, ?)",
            [
                ("alpha", METIS_VERSION, "same-key", '{"value":"alpha"}'),
                ("beta", METIS_VERSION, "same-key", '{"value":"beta"}'),
                ("alpha", "old-version", "stale", '{"value":"stale"}'),
                ("alpha", METIS_VERSION, "malformed", "{invalid"),
            ],
        )
    session = ReviewCheckpointSession("alpha", _checkpoint_callbacks(tmp_path))
    assert session.get("same-key") == {"value": "alpha"}
    assert session.get("stale") is None
    assert session.get("malformed") is None
    session.put("new-key", {"value": "new"})
    restarted = ReviewCheckpointSession("alpha", _checkpoint_callbacks(tmp_path))
    assert restarted.get("same-key") == {"value": "alpha"}
    assert restarted.get("new-key") == {"value": "new"}
    with closing(sqlite3.connect(path)) as connection, connection:
        assert connection.execute(
            "SELECT payload FROM review_checkpoint_records WHERE producer = 'beta'"
        ).fetchone() == ('{"value":"beta"}',)


def test_readonly_checkpoint_write_preserves_committed_resume(
    tmp_path, monkeypatch, caplog
):
    session = ReviewCheckpointSession("fixture", _checkpoint_callbacks(tmp_path))
    session.put("key", {"value": "committed"})
    path = tmp_path / ".metis/checkpoints/review.fixture.sqlite3"
    committed = path.read_bytes()
    # SQLite itself raises READONLY; the injection only selects connection mode.
    with monkeypatch.context() as patch:
        patch.setattr(
            review_checkpoints,
            "_connect_checkpoint",
            lambda path: sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True),
        )
        session.put("key", {"value": "uncommitted"})
    assert "Unable to save review checkpoint" in caplog.text
    assert path.read_bytes() == committed
    restarted = ReviewCheckpointSession("fixture", _checkpoint_callbacks(tmp_path))
    assert restarted.get("key") == {"value": "committed"}
    restarted.put("key", {"value": "retried"})
    assert ReviewCheckpointSession("fixture", _checkpoint_callbacks(tmp_path)).get(
        "key"
    ) == {"value": "retried"}


def test_materialization_retry_keeps_issued_references_across_service_restart(tmp_path):
    (tmp_path / "module.fixture").write_text("entry\n", encoding="utf-8")
    attempts = []

    def build_graph(*, codebase_path, files, progress_callback=None):
        attempts.append(files)
        if len(attempts) == 1:
            return CodeGraphResult(
                CodeGraph(),
                (),
                diagnostics=tuple(
                    CodeGraphDiagnostic(path, "incomplete fixture") for path in files
                ),
                failed_files=files,
            )
        graph = CodeGraph()
        graph.add_node(
            FunctionNode("module.fixture::entry", "module.fixture", "entry", 1)
        )
        return CodeGraphResult(graph, files)

    def factory(_context):
        return SimpleNamespace(build_graph=build_graph)

    first_service = _graph_service(tmp_path, factory)
    incomplete = first_service.materialize()
    second_service = _graph_service(tmp_path, factory)
    complete = second_service.materialize()
    assert incomplete.failed_files
    assert not complete.failed_files
    assert incomplete.fingerprint == complete.fingerprint
    assert complete.revision > incomplete.revision
    restarted = _graph_service(tmp_path, factory)
    assert restarted.load(incomplete).node_count() == 0
    assert restarted.load(complete).get_node("module.fixture::entry") is not None
    assert restarted.materialize() == complete
    assert len(attempts) == 2


def test_interrupted_materialization_can_retry_on_same_service(tmp_path):
    (tmp_path / "module.fixture").write_text("entry\n", encoding="utf-8")
    attempts = 0

    def build_graph(*, codebase_path, files, progress_callback=None):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise KeyboardInterrupt("inert provider interruption")
        return CodeGraphResult(CodeGraph(), files)

    def factory(_context):
        return SimpleNamespace(build_graph=build_graph)

    service = _graph_service(tmp_path, factory)
    with pytest.raises(KeyboardInterrupt, match="inert provider interruption"):
        service.materialize()
    # A bounded daemon thread keeps a latch regression from hanging the suite.
    completed = Event()
    references = []

    def retry():
        references.append(service.materialize())
        completed.set()

    worker = Thread(target=retry, daemon=True)
    worker.start()
    assert completed.wait(5)
    worker.join(timeout=1)
    assert service.load(references[0]).node_count() == 0


@pytest.mark.parametrize("revision", [2**63 - 1, 2**63, 2**80])
def test_unknown_graph_revisions_handle_sqlite_integer_limits(tmp_path, revision):
    store = SQLiteCodeGraphStore(str(tmp_path))
    original = _save_graph(store)
    unknown = CodeGraphReference.model_validate(
        {**original.model_dump(), "revision": revision}
    )
    with pytest.raises(ValueError, match="reference does not exist"):
        store.load(unknown, codebase_path=str(tmp_path))
    assert store.load(original, codebase_path=str(tmp_path)).node_count() == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"message": None},
        {"phase": "unsupported"},
        {"partial_output": "yes"},
        {"start_byte": 1.5, "end_byte": 2.5},
        {"severity": []},
        {"file_path": [], "severity": "error"},
    ],
)
def test_invalid_provider_diagnostics_remain_loadable_and_can_retry(tmp_path, changes):
    (tmp_path / "module.fixture").write_text("inert fixture", encoding="utf-8")
    fields = {
        "file_path": "module.fixture",
        "message": "fixture",
        "severity": "warning",
    }
    fields.update(changes)
    diagnostics = (CodeGraphDiagnostic(**fields),)

    def build_graph(*, files, **kwargs):
        return CodeGraphResult(CodeGraph(), files, diagnostics=diagnostics)

    def factory(_context):
        return SimpleNamespace(build_graph=build_graph)

    service = _graph_service(tmp_path, factory)
    incomplete = service.materialize()
    assert incomplete.failed_files == (str(tmp_path / "module.fixture"),)
    assert "invalid diagnostic" in incomplete.diagnostics[0].message
    assert service.load(incomplete).node_count() == 0
    diagnostics = ()
    complete = service.materialize()
    assert not complete.failed_files
    assert complete.revision > incomplete.revision
    restarted = _graph_service(tmp_path, factory)
    assert restarted.load(incomplete).node_count() == 0
    assert restarted.load(complete).node_count() == 0
    assert restarted.materialize() == complete


@pytest.mark.parametrize("field", ["fingerprint", "producer_version"])
def test_invalid_graph_reference_metadata_rolls_back_before_retry(tmp_path, field):
    store = SQLiteCodeGraphStore(str(tmp_path))
    original = _save_graph(store)
    with closing(sqlite3.connect(store.location)) as connection:
        before = tuple(connection.iterdump())
    with pytest.raises(ValueError, match=field):
        _save_graph(store, **{field: ""})
    with closing(sqlite3.connect(store.location)) as connection:
        assert tuple(connection.iterdump()) == before
    assert store.load(original, codebase_path=str(tmp_path)).node_count() == 1
    retried = _save_graph(store)
    assert retried.revision == original.revision + 1
    assert store.load(retried, codebase_path=str(tmp_path)).node_count() == 1


@pytest.mark.parametrize("locations", [[], ["", "  "]])
def test_graph_declarations_without_locations_survive_restart(tmp_path, locations):
    graph = CodeGraph()
    graph.add_public_declarations(
        {"declared": locations, "located": ["module.fixture:1"]}
    )
    store = SQLiteCodeGraphStore(str(tmp_path))
    reference = store.save(
        fingerprint="declarations",
        producer_version=METIS_VERSION,
        graph=graph,
        processed_files=(),
        failed_files=(),
        diagnostics=(),
    )
    reopened = SQLiteCodeGraphStore(str(tmp_path))
    loaded = reopened.load(reference, codebase_path=str(tmp_path))
    assert loaded.public_declarations == {
        "declared": [],
        "located": ["module.fixture:1"],
    }
    assert (
        reopened.reference_for_fingerprint("declarations", codebase_path=str(tmp_path))
        == reference
    )


def test_v2_graph_constraint_migration_preserves_references_with_two_initializers(
    tmp_path,
):
    (tmp_path / "module.fixture").write_text("entry\n", encoding="utf-8")
    initial = SQLiteCodeGraphStore(str(tmp_path))
    reference = _save_graph(initial)
    with closing(sqlite3.connect(initial.location)) as connection, connection:
        connection.execute(
            "CREATE UNIQUE INDEX legacy_fingerprint ON canonical_codegraph(fingerprint)"
        )
    ready = Barrier(2)

    def open_store():
        ready.wait(timeout=5)
        return SQLiteCodeGraphStore(str(tmp_path))

    with ThreadPoolExecutor(max_workers=2) as pool:
        stores = [
            future.result(timeout=5)
            for future in [pool.submit(open_store), pool.submit(open_store)]
        ]
    later = _save_graph(stores[0], failed=("other.fixture",))
    for issued in (reference, later):
        assert (
            stores[1]
            .load(issued, codebase_path=str(tmp_path))
            .get_node("module.fixture::entry")
        )
    assert (
        stores[1].reference_for_fingerprint("stable-input", codebase_path=str(tmp_path))
        == reference
    )
    with closing(graph_store._connect(initial.location)) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO codegraph_records VALUES (9999, 0, 'failed', 'absent', X'')"
            )


def test_newer_graph_schema_is_preserved_for_its_own_reader(tmp_path):
    (tmp_path / "module.fixture").write_text("entry\n", encoding="utf-8")
    store = SQLiteCodeGraphStore(str(tmp_path))
    reference = _save_graph(store)
    with closing(sqlite3.connect(store.location)) as connection, connection:
        connection.execute("PRAGMA user_version = 999")
    before = Path(store.location).read_bytes()
    with pytest.raises(RuntimeError, match="newer schema"):
        SQLiteCodeGraphStore(str(tmp_path))
    assert Path(store.location).read_bytes() == before
    assert store.load(reference, codebase_path=str(tmp_path)).get_node(
        "module.fixture::entry"
    )


def test_graph_migration_failure_rolls_back_metadata_and_records(tmp_path, monkeypatch):
    (tmp_path / "module.fixture").write_text("entry\n", encoding="utf-8")
    store = SQLiteCodeGraphStore(str(tmp_path))
    reference = _save_graph(store)
    with closing(sqlite3.connect(store.location)) as connection, connection:
        connection.execute(
            "CREATE UNIQUE INDEX legacy_fingerprint ON canonical_codegraph(fingerprint)"
        )

    class InterruptedMigration(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith("ALTER TABLE canonical_codegraph_revisions"):
                raise sqlite3.OperationalError("inert migration interruption")
            return super().execute(sql, *args)

    with monkeypatch.context() as patch:
        patch.setattr(
            graph_store,
            "_connect",
            lambda path: sqlite3.connect(path, factory=InterruptedMigration),
        )
        with pytest.raises(RuntimeError, match="inert migration interruption"):
            SQLiteCodeGraphStore(str(tmp_path))
    assert store.load(reference, codebase_path=str(tmp_path)).get_node(
        "module.fixture::entry"
    )
    with closing(sqlite3.connect(store.location)) as connection, connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name = 'canonical_codegraph_revisions'"
            ).fetchall()
            == []
        )
    reopened = SQLiteCodeGraphStore(str(tmp_path))
    assert reopened.load(reference, codebase_path=str(tmp_path)).node_count() == 1


def test_sqlite_memory_round_trip_survives_service_and_connection_restart(tmp_path):
    path = tmp_path / "memory.sqlite3"
    service = MemoryService(SQLiteMemoryStore(path))
    record = _memory_record("active")
    service.put_record(record)
    service.close()
    restarted = MemoryService(SQLiteMemoryStore(path))
    loaded = restarted.get_record(record.namespace, record.key)
    assert loaded is not None
    assert loaded.namespace == record.namespace
    assert loaded.key == record.key
    assert loaded.to_store_value() == record.to_store_value()
    assert restarted.search_records(record.namespace, query="active")[0].key == "active"
    assert restarted.store.list_namespaces(prefix=("repo",)) == [record.namespace]


def test_sqlite_namespace_replacement_is_one_snapshot_across_instances(tmp_path):
    path = tmp_path / "memory.sqlite3"
    first_inserted, release_first, second_started = Event(), Event(), Event()

    class PausingStore(SQLiteMemoryStore):
        def _put(self, connection, namespace, key, value):
            super()._put(connection, namespace, key, value)
            if key == "a-first":
                first_inserted.set()
                assert release_first.wait(5)

    first = MemoryService(PausingStore(path))
    second = MemoryService(SQLiteMemoryStore(path))
    observer = MemoryService(SQLiteMemoryStore(path))
    for key in ("old-first", "old-second"):
        first.put_record(_memory_record(key))
    first.put_record(_memory_record("untouched", ("repo", "other")))
    # Initialize the other connection before pausing the first write transaction.
    assert second.get_record(("repo", "notes"), "old-first") is not None

    def replace_second():
        second_started.set()
        return second.replace_records(
            ("repo", "notes"), [_memory_record("b-first"), _memory_record("b-second")]
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        writing = pool.submit(
            first.replace_records,
            ("repo", "notes"),
            [_memory_record("a-first"), _memory_record("a-second")],
        )
        assert first_inserted.wait(5)
        assert {record.key for record in observer.iter_records(("repo", "notes"))} == {
            "old-first",
            "old-second",
        }
        competing = pool.submit(replace_second)
        assert second_started.wait(5)
        release_first.set()
        assert writing.result(timeout=5) == competing.result(timeout=5) == 2
    restarted = MemoryService(SQLiteMemoryStore(path))
    assert {record.key for record in restarted.iter_records(("repo", "notes"))} == {
        "b-first",
        "b-second",
    }
    assert restarted.search_records(("repo", "notes"), query="old") == []
    assert restarted.search_records(("repo", "notes"), query="a") == []
    assert restarted.get_record(("repo", "other"), "untouched") is not None


def test_sqlite_namespace_failed_replacement_rolls_back_data_and_search_index(tmp_path):
    path = tmp_path / "memory.sqlite3"
    service = MemoryService(SQLiteMemoryStore(path))
    service.put_record(_memory_record("old"))
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            "CREATE TRIGGER reject_fixture BEFORE INSERT ON memory_records "
            "WHEN NEW.key = 'rejected' BEGIN SELECT RAISE(FAIL, 'inert rejected row'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="inert rejected row"):
        service.replace_records(
            ("repo", "notes"), [_memory_record("inserted"), _memory_record("rejected")]
        )
    reopened = MemoryService(SQLiteMemoryStore(path))
    assert [record.key for record in reopened.iter_records(("repo", "notes"))] == [
        "old"
    ]
    assert [
        record.key for record in reopened.search_records(("repo",), query="old")
    ] == ["old"]
    assert reopened.search_records(("repo",), query="inserted") == []
    assert reopened.reset_records(("repo", "notes")) == 1
    assert (
        MemoryService(SQLiteMemoryStore(path)).search_records(("repo",), query="old")
        == []
    )


def test_temporary_memory_replacement_is_serial_across_service_wrappers(monkeypatch):
    first_read, release_first, second_read = Event(), Event(), Event()

    class PausingStore(InMemoryStore):
        paused = False

        def search(self, *args, **kwargs):
            snapshot = super().search(*args, **kwargs)
            if not self.paused:
                self.paused = True
                first_read.set()
                assert release_first.wait(5)
            else:
                second_read.set()
            return snapshot

    store = PausingStore()
    replacement_lock = _ObservedLock(RLock())
    monkeypatch.setitem(
        memory_service._IN_MEMORY_REPLACEMENT_LOCKS, store, replacement_lock
    )
    first, second = MemoryService(store), MemoryService(store)
    first.put_record(_memory_record("old"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        first_job = pool.submit(
            first.replace_records, ("repo", "notes"), [_memory_record("first")]
        )
        try:
            assert first_read.wait(5)
            second_job = pool.submit(
                second.replace_records, ("repo", "notes"), [_memory_record("second")]
            )
            assert replacement_lock.contended.wait(5)
            assert not second_read.is_set()
        finally:
            release_first.set()
        assert first_job.result(timeout=5) == second_job.result(timeout=5) == 1
    assert [record.key for record in first.iter_records(("repo",))] == ["second"]
    assert first.reset_records(("repo", "notes")) == 1
    assert list(second.iter_records(("repo",))) == []
