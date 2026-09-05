# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from langgraph.store.base import PutOp
from langgraph.store.memory import InMemoryStore
import pytest

from metis.memory import MemoryRecord
from metis.memory import MemoryService
from metis.memory import SQLiteMemoryStore


@pytest.fixture(params=["sqlite", "memory"])
def service(request, tmp_path):
    store = (
        SQLiteMemoryStore(tmp_path / "memory.sqlite3")
        if request.param == "sqlite"
        else InMemoryStore()
    )
    return MemoryService(store)


def _record(key="note", namespace=("repo", "notes"), **values):
    return MemoryRecord.create(
        namespace=namespace,
        key=key,
        tool_version="test",
        artifact_type="note",
        repo_fingerprint="repo",
        input_fingerprint="input",
        memory_type="semantic",
        **values,
    )


_INVALID_NAMESPACES = [
    (),
    ("repo", 1),
    ("repo", "bad.label"),
    ("repo", ""),
    ("langgraph", "notes"),
    ["repo", "notes"],
    "repo",
]


@pytest.mark.parametrize("namespace", _INVALID_NAMESPACES)
def test_replacement_rejects_invalid_namespaces_and_preserves_old_records(
    service, namespace
):
    service.put_record(_record("old"))
    with pytest.raises(ValueError, match="namespace"):
        service.replace_records((), [_record("new"), _record("invalid", namespace)])
    assert [record.key for record in service.iter_records()] == ["old"]
    assert service.reset_records() == 1
    assert list(service.iter_records()) == []


@pytest.mark.parametrize("namespace", _INVALID_NAMESPACES)
def test_native_sqlite_replacement_validates_every_namespace_before_mutation(
    tmp_path, monkeypatch, namespace
):
    store = SQLiteMemoryStore(tmp_path / "memory.sqlite3")
    store.put(("repo",), "old", {"value": "old"})

    def unexpected_delete(*_args):
        pytest.fail("invalid replacement started deleting the old snapshot")

    monkeypatch.setattr(store, "_delete", unexpected_delete)
    with pytest.raises(ValueError, match="namespace"):
        store.replace_records(
            (),
            [
                PutOp(("repo",), "valid", {"value": "valid"}),
                PutOp(namespace, "invalid", {"value": "invalid"}),
            ],
        )
    assert store.get(("repo",), "old").value == {"value": "old"}
    assert store.get(("repo",), "valid") is None


def test_sqlite_batch_rejects_invalid_namespace_and_rolls_back(tmp_path):
    store = SQLiteMemoryStore(tmp_path / "memory.sqlite3")
    store.put(("repo",), "old", {"value": "old"})
    with pytest.raises(ValueError, match="namespace"):
        store.batch(
            [
                PutOp(("repo",), "old", None),
                PutOp(("repo", 1), "invalid", {"value": "invalid"}),
            ]
        )
    assert [(item.namespace, item.key) for item in store.search(())] == [
        (("repo",), "old")
    ]


@pytest.mark.parametrize("prefix", [("repo", ""), ["repo"], "repo"])
def test_invalid_reset_prefix_cannot_clear_records(service, prefix):
    service.put_record(_record("old"))
    with pytest.raises(ValueError, match="namespace"):
        service.reset_records(prefix)
    assert [record.key for record in service.iter_records()] == ["old"]


def test_namespace_reset_preserves_parent_and_similarly_named_siblings(service):
    for key, namespace in (
        ("parent", ("repo_%",)),
        ("old", ("repo_%", "安全")),
        ("sibling", ("repo_%", "安全-other")),
    ):
        service.put_record(_record(key, namespace))
    assert (
        service.replace_records(
            ("repo_%", "安全"),
            [_record("new", ("repo_%", "安全", "child"))],
        )
        == 1
    )
    assert service.reset_records(("repo_%", "安全")) == 1
    assert {record.key for record in service.iter_records()} == {"parent", "sibling"}


@pytest.mark.parametrize("write_method", ["create", "put", "replace"])
def test_memory_writes_snapshot_nested_record_values(service, write_method):
    body = {"sections": [{"text": "original"}]}
    metadata = {"labels": ["original"]}
    record = _record(body_json=body, metadata=metadata)
    if write_method == "create":
        values = record.to_store_value()
        values.pop("tool_version")
        values.update(body_json=body, metadata=metadata)
        record = service.create_record(
            namespace=record.namespace,
            key=record.key,
            **values,
        )
    elif write_method == "put":
        service.put_record(record)
    else:
        service.replace_records(record.namespace, [record])
    before = service.store.get(record.namespace, record.key)
    body["sections"][0]["text"] = "changed input"
    metadata["labels"].append("changed input")
    record.body_json["sections"][0]["text"] = "changed record"
    record.metadata["labels"].append("changed record")
    stored = service.get_record(record.namespace, record.key)
    assert stored.body_json == {"sections": [{"text": "original"}]}
    assert stored.metadata == {"labels": ["original"]}
    assert stored.input_fingerprint == "input"
    assert (
        service.store.get(record.namespace, record.key).updated_at == before.updated_at
    )


@pytest.mark.parametrize("read_method", ["get", "search", "iter"])
def test_memory_reads_return_owned_nested_values(service, read_method):
    record = _record(body_json=[{"text": "original"}], metadata={"labels": ["a"]})
    service.put_record(record)
    if read_method == "get":
        loaded = service.get_record(record.namespace, record.key)
    elif read_method == "search":
        loaded = service.search_records(record.namespace)[0]
    else:
        loaded = next(service.iter_records(record.namespace))
    loaded.body_json[0]["text"] = "changed"
    loaded.metadata["labels"].append("changed")
    stored = service.get_record(record.namespace, record.key)
    assert stored.body_json == [{"text": "original"}]
    assert stored.metadata == {"labels": ["a"]}
