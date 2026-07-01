# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.memory import MemoryService
from metis.memory import SQLiteMemoryStore
from metis.memory.fingerprints import input_fingerprint


def test_sqlite_memory_store_round_trips_namespace_key_value(tmp_path):
    store = SQLiteMemoryStore(tmp_path / "memory.sqlite3")
    namespace = ("metis", "profiles", "repo")
    value = {
        "artifact_type": "target_profile",
        "schema_version": 1,
        "repo_fingerprint": "repo1",
        "input_fingerprint": "input1",
        "memory_type": "semantic",
        "metadata": {"authority": "documented"},
        "summary_text": "Documented trust boundary",
        "search_text": "trust boundary cli filesystem",
    }

    store.put(namespace, "active", value)

    item = store.get(namespace, "active")
    assert item is not None
    assert item.namespace == namespace
    assert item.key == "active"
    assert item.value == value


def test_sqlite_memory_store_search_filter_namespaces_and_delete(tmp_path):
    store = SQLiteMemoryStore(tmp_path / "memory.sqlite3")
    store.put(
        ("metis", "profiles", "repo1"),
        "target_profile",
        {
            "artifact_type": "target_profile",
            "schema_version": 1,
            "repo_fingerprint": "repo1",
            "input_fingerprint": "input1",
            "memory_type": "semantic",
            "metadata": {"authority": "documented"},
            "summary_text": "CLI accepts untrusted SARIF files",
            "search_text": "cli sarif trust boundary",
        },
    )
    store.put(
        ("metis", "history", "repo1"),
        "snapshot",
        {
            "artifact_type": "history_snapshot",
            "schema_version": 1,
            "repo_fingerprint": "repo1",
            "input_fingerprint": "input2",
            "memory_type": "episodic",
            "metadata": {"authority": "history"},
            "summary_text": "Churn hotspot in parser",
            "search_text": "parser churn corrective commits",
        },
    )

    results = store.search(
        ("metis",),
        query="sarif boundary",
        filter={"metadata.authority": "documented"},
    )

    assert [(item.namespace, item.key) for item in results] == [
        (("metis", "profiles", "repo1"), "target_profile")
    ]
    assert store.list_namespaces(prefix=("metis",), max_depth=2) == [
        ("metis", "history"),
        ("metis", "profiles"),
    ]

    store.delete(("metis", "profiles", "repo1"), "target_profile")

    assert store.get(("metis", "profiles", "repo1"), "target_profile") is None


def test_memory_service_freshness_and_invalidation(tmp_path):
    store = SQLiteMemoryStore(tmp_path / "memory.sqlite3")
    service = MemoryService(store, repo_root="/repo", tool_version="metis-test")

    record = service.create_record(
        namespace=("metis", "profiles", "repo1"),
        key="target_profile",
        artifact_type="target_profile",
        repo_fingerprint="repo1",
        input_fingerprint=input_fingerprint({"docs": ["SECURITY.md"]}),
        memory_type="semantic",
        authority="documented",
        body_json={"authority": "documented"},
        metadata={"authority": "documented"},
        summary_text="Documented profile",
        search_text="security docs profile",
    )

    loaded = service.get_record(record.namespace, record.key)
    assert loaded is not None
    assert loaded.authority == "documented"
    assert loaded.body_json == {"authority": "documented"}
    assert service.is_fresh(
        loaded,
        repo_fingerprint="repo1",
        input_fingerprint=record.input_fingerprint,
        tool_version="metis-test",
    )
    assert not service.is_fresh(loaded, repo_fingerprint="other")
    assert not service.is_fresh(
        loaded,
        input_fingerprint="other",
    )

    service.invalidate(record.namespace, record.key)
    assert service.get_record(record.namespace, record.key) is None


def test_memory_service_keeps_created_at_stable_on_overwrite(tmp_path):
    store = SQLiteMemoryStore(tmp_path / "memory.sqlite3")
    service = MemoryService(store, repo_root="/repo", tool_version="metis-test")

    first = service.create_record(
        namespace=("metis", "profiles", "repo1"),
        key="target_profile",
        artifact_type="target_profile",
        repo_fingerprint="repo1",
        input_fingerprint="input1",
        memory_type="semantic",
        body_json={},
        summary_text="Initial profile",
    )
    service.create_record(
        namespace=("metis", "profiles", "repo1"),
        key="target_profile",
        artifact_type="target_profile",
        repo_fingerprint="repo1",
        input_fingerprint="input2",
        memory_type="semantic",
        body_json={},
        summary_text="Updated profile",
    )

    loaded = service.get_record(("metis", "profiles", "repo1"), "target_profile")
    store_item = store.get(("metis", "profiles", "repo1"), "target_profile")

    assert loaded is not None
    assert store_item is not None
    assert loaded.created_at == first.created_at
    assert "created_at" not in store_item.value
    assert store_item.created_at.isoformat().replace("+00:00", "Z") == first.created_at


def test_memory_service_deletes_stale_records(tmp_path):
    store = SQLiteMemoryStore(tmp_path / "memory.sqlite3")
    service = MemoryService(store, repo_root="/repo", tool_version="metis-test")
    for key, repo_fingerprint in (
        ("fresh-profile", "fresh"),
        ("old-profile", "old"),
    ):
        service.create_record(
            namespace=("metis", "profiles", "repo1"),
            key=key,
            artifact_type="target_profile",
            repo_fingerprint=repo_fingerprint,
            input_fingerprint=f"input-{key}",
            memory_type="semantic",
            body_json={},
            summary_text=key,
        )

    deleted = service.delete_stale_records(
        ("metis",),
        repo_fingerprint="fresh",
    )

    remaining = list(service.iter_records(("metis",)))
    assert deleted == 1
    assert [(record.key, record.repo_fingerprint) for record in remaining] == [
        ("fresh-profile", "fresh")
    ]
