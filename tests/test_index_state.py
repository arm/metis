# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from qdrant_client.models import Distance

from metis.cli import commands
from metis.cli import entry
from metis.cli.command_runtime import CommandRuntime
from metis.engine import git_history
from metis.engine.capabilities import indexing
from metis.exceptions import IndexStateError
from metis.exceptions import IndexUpdateError
from metis.exceptions import ParsingError
from metis.vector_store import qdrant_store
from metis.vector_store.chroma_store import ChromaStore
from metis.vector_store.qdrant_store import QdrantStore

SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SHA = "fedcba9876543210fedcba9876543210fedcba98"
PATCH = "--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n-int a;\n+int b;\n"


def test_normalize_commit_accepts_sha1_and_sha256_ids():
    sha256 = SHA + "0" * 24
    assert git_history.normalize_commit(f" {SHA.upper()}\n") == SHA
    assert git_history.normalize_commit(sha256.upper()) == sha256


def recorded_state(backend):
    (state,), _ = backend.set_index_state.call_args
    return state["commit"], state["operation"]


@pytest.mark.parametrize(
    ("explicit", "head", "expected"),
    [(SHA, OTHER_SHA, SHA), (None, OTHER_SHA, OTHER_SHA), (None, None, None)],
    ids=["explicit-commit", "git-head", "unknown"],
)
def test_index_records_the_commit(
    engine, dummy_backend, monkeypatch, explicit, head, expected
):
    engine._config.index_commit = explicit
    monkeypatch.setattr(indexing, "head_commit", lambda path: head)

    engine.indexing.index_codebase()

    assert recorded_state(dummy_backend) == (expected, "index")


@pytest.mark.parametrize(
    ("explicit", "expected"), [(SHA, SHA), (None, None)], ids=["commit", "plain"]
)
def test_update_records_its_commit_or_unknown(
    engine, dummy_backend, monkeypatch, explicit, expected
):
    engine._config.index_commit = explicit
    monkeypatch.setattr(indexing, "head_commit", lambda path: OTHER_SHA)
    (Path(engine._config.codebase_path) / "x.c").write_text("int b;\n")

    engine.indexing.update_index(PATCH)

    assert recorded_state(dummy_backend) == (expected, "update")


@pytest.mark.parametrize(
    ("explicit", "patch", "handles_error", "error", "cleared"),
    [
        (None, object(), None, ParsingError, False),
        (None, PATCH, None, IndexUpdateError, True),
        (None, PATCH, RuntimeError("embedding"), RuntimeError, True),
        (SHA, PATCH, None, IndexUpdateError, False),
    ],
    ids=["parse-error", "plain-partial", "plain-other-error", "with-commit"],
)
def test_failed_update_clears_the_commit_only_after_a_plain_update_wrote(
    engine, dummy_backend, explicit, patch, handles_error, error, cleared
):
    engine._config.index_commit = explicit
    dummy_backend.get_index_handles.side_effect = handles_error

    with pytest.raises(error):
        engine.indexing.update_index(patch)

    if cleared:
        assert recorded_state(dummy_backend) == (None, "update")
    else:
        dummy_backend.set_index_state.assert_not_called()


def test_failed_state_write_does_not_hide_the_update_error(engine, dummy_backend):
    dummy_backend.set_index_state.side_effect = IndexStateError("write failed")

    with pytest.raises(IndexUpdateError):
        engine.indexing.update_index(PATCH)


def test_commit_flag_rejects_a_short_id(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["metis", "--commit", "abc123"])

    with pytest.raises(SystemExit, match="2"):
        entry.main()

    assert "--commit: A commit must be a full" in capsys.readouterr().err


def test_commit_flag_reaches_the_engine_config_normalized(
    monkeypatch, tmp_path, dummy_llm, dummy_backend, capability_settings
):
    runtime = {
        "llm_provider_name": "test-provider",
        "llm_provider": {},
        "language_plugin": "c",
        "max_workers": 2,
        "max_token_length": 2048,
        "llama_query_model": "gpt-test",
        "similarity_top_k": 3,
        "capability_settings": capability_settings,
    }
    monkeypatch.setattr(entry, "get_chat_provider", lambda _name: lambda _c: dummy_llm)
    monkeypatch.setattr(entry, "build_chroma_backend", lambda *_a: dummy_backend)
    args = SimpleNamespace(
        backend="chroma",
        codebase_path=str(tmp_path),
        custom_prompt=None,
        commit=f" {SHA.upper()} ",
    )

    engine, _backend = entry.build_engine(args, runtime)

    assert engine._config.index_commit == SHA
    engine.close()


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ({"commit": SHA, "operation": "index", "updated_at": "x"}, f"commit: {SHA}"),
        ({"commit": None, "operation": "update", "updated_at": "x"}, "unknown"),
        (None, "No index state is recorded"),
    ],
    ids=["commit", "unknown", "none"],
)
def test_index_status_shows_the_recorded_commit(monkeypatch, state, expected):
    printed = []
    monkeypatch.setattr(
        commands, "print_console", lambda msg, *_a, **_k: printed.append(msg)
    )
    engine = SimpleNamespace(indexing=SimpleNamespace(get_index_state=lambda: state))

    commands.run_index_status(
        engine, SimpleNamespace(quiet=False), CommandRuntime("index_status", [])
    )

    assert expected in "\n".join(printed)


def test_chroma_state_is_shared_by_store_instances_and_cleared_by_reset(tmp_path):
    reader = ChromaStore(str(tmp_path), None, None, {})
    writer = ChromaStore(str(tmp_path), None, None, {})
    assert reader.get_index_state() is None
    reader.set_index_state({"commit": OTHER_SHA})
    assert reader.get_index_state() == {"commit": OTHER_SHA}

    writer.set_index_state({"commit": SHA})
    assert reader.get_index_state() == {"commit": SHA}

    writer.reset_index()
    assert reader.get_index_state() is None
    writer.close()
    reader.close()


@pytest.fixture
def qdrant(monkeypatch):
    client = Mock()
    monkeypatch.setattr(qdrant_store, "QdrantClient", Mock(return_value=client))
    monkeypatch.setattr(qdrant_store, "QdrantVectorStore", Mock())
    monkeypatch.setattr(qdrant_store.StorageContext, "from_defaults", Mock())
    backend = QdrantStore(
        url="http://q:6333",
        api_key=None,
        collection_prefix="project",
        embed_dim=8,
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
    )
    return SimpleNamespace(backend=backend, client=client)


def test_qdrant_state_round_trip_uses_a_dot_distance_point(qdrant):
    qdrant.client.collection_exists.side_effect = lambda name: name != "project_state"
    assert qdrant.backend.get_index_state() is None

    qdrant.backend.set_index_state({"commit": SHA})

    create = qdrant.client.create_collection.call_args.kwargs
    upsert = qdrant.client.upsert.call_args.kwargs
    assert create["collection_name"] == upsert["collection_name"] == "project_state"
    # Cosine distance cannot normalize a zero vector.
    assert create["vectors_config"].distance == Distance.DOT
    assert any(upsert["points"][0].vector)
    qdrant.client.collection_exists.side_effect = None
    qdrant.client.retrieve.return_value = upsert["points"]
    assert qdrant.backend.get_index_state() == {"commit": SHA}

    qdrant.backend.reset_index()

    deleted = {c.args[0] for c in qdrant.client.delete_collection.call_args_list}
    assert deleted == {"project_code", "project_docs", "project_state"}


@pytest.mark.parametrize(
    ("store_schema", "expected"),
    [(None, "mixedcase"), ("from_store", "from_store")],
    ids=["lowercased", "vector-store-schema"],
)
def test_postgres_state_table_uses_the_vector_schema(store_schema, expected):
    pgvector_store = pytest.importorskip("metis.vector_store.pgvector_store")
    backend = pgvector_store.PGVectorStoreImpl(
        "postgresql://db", "MixedCase", None, None, 8
    )
    if store_schema:
        backend.vector_store_code = SimpleNamespace(schema_name=store_schema)

    table = backend._state_table()

    assert (table.schema, table.name) == (expected, "index_state")
