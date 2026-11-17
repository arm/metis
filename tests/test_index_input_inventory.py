# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from unittest.mock import Mock

import pytest

from test_indexing_selection import index_engine as index_engine


@pytest.fixture
def inventory(index_engine, tmp_path, monkeypatch):
    selected = ["src/plain.py", "src/[literal]! #.py", "src/.hidden.py", "README.MD"]
    for relative in [*selected, "ignored.py", "unsupported.unknown"]:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("retained text\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("*\n", encoding="utf-8")
    prepared = []
    embeddings = Mock(return_value=(None, None))
    monkeypatch.setattr(index_engine.indexing, "_get_embedding_models", embeddings)

    def prepare(code_docs, doc_docs, *_args):
        prepared.extend(
            Path(doc.metadata["file_path"]) for doc in [*code_docs, *doc_docs]
        )
        yield from [None] * (len(code_docs) + len(doc_docs))
        return [], []

    def no_discovery(*_args, **_kwargs):
        pytest.fail("Explicit inventory performed discovery or ignore matching")

    monkeypatch.setattr(
        "metis.engine.capabilities.indexing.prepare_nodes_iter", prepare
    )
    monkeypatch.setattr("metis.engine.capabilities.indexing.os.walk", no_discovery)
    monkeypatch.setattr(index_engine.repository, "load_metisignore", no_discovery)
    monkeypatch.setattr(index_engine.repository, "is_metisignored", no_discovery)
    return index_engine.indexing, selected, prepared, embeddings


def test_count_and_preparation_use_only_the_explicit_inventory(inventory, tmp_path):
    indexing, selected, prepared, embeddings = inventory

    assert indexing.count_index_items(input_files=selected) == len(selected)
    assert list(indexing.index_prepare_nodes_iter(input_files=selected)) == [
        None
    ] * len(selected)

    assert set(prepared) == {tmp_path / relative for relative in selected}
    embeddings.assert_called_once_with()


@pytest.mark.parametrize(
    "selected",
    [
        "src/plain.py",
        ("src/plain.py",),
        [None],
        [42],
        [""],
        ["../outside.py"],
        ["/absolute.py"],
        ["./src/plain.py"],
        ["src//plain.py"],
        ["src/../ignored.py"],
        ["src/plain.py", "src/plain.py"],
        ["missing.py"],
        ["a" * 300 + ".py"],
        ["unsupported.unknown"],
        ["src"],
        ["bad\x00.py"],
    ],
)
def test_invalid_inventory_fails_before_embedding_initialization(inventory, selected):
    indexing, _selected, prepared, embeddings = inventory

    with pytest.raises(ValueError):
        indexing.count_index_items(input_files=selected)
    with pytest.raises(ValueError):
        list(indexing.index_prepare_nodes_iter(input_files=selected))

    assert prepared == []
    embeddings.assert_not_called()


@pytest.mark.parametrize("directory", [False, True])
@pytest.mark.parametrize("outside", [False, True])
def test_inventory_rejects_symlink_components(inventory, tmp_path, directory, outside):
    indexing, _selected, prepared, embeddings = inventory
    target = (
        tmp_path.parent / f"{tmp_path.name}-outside" if outside else tmp_path / "real"
    )
    target.mkdir()
    (target / "source.py").write_text("value = 1\n", encoding="utf-8")
    link = tmp_path / ("link" if directory else "link.py")
    link.symlink_to(
        target if directory else target / "source.py", target_is_directory=directory
    )
    selected = ["link/source.py" if directory else "link.py"]

    with pytest.raises(ValueError, match="symlink"):
        indexing.count_index_items(input_files=selected)
    with pytest.raises(ValueError, match="symlink"):
        list(indexing.index_prepare_nodes_iter(input_files=selected))

    assert prepared == []
    embeddings.assert_not_called()


def test_explicit_empty_inventory_does_not_fall_back_to_discovery(inventory):
    indexing, _selected, prepared, embeddings = inventory

    assert indexing.count_index_items(input_files=[]) == 0
    assert list(indexing.index_prepare_nodes_iter(input_files=[])) == []
    assert indexing._state.pending_nodes == ([], [])
    assert prepared == []
    embeddings.assert_not_called()


def test_native_discovery_still_initializes_embeddings_first(index_engine, monkeypatch):
    calls = []
    discover = index_engine.indexing._get_supported_input_files

    def embeddings():
        calls.append("embeddings")
        return None, None

    def discovery(*args):
        calls.append("discovery")
        return discover(*args)

    monkeypatch.setattr(index_engine.indexing, "_get_embedding_models", embeddings)
    monkeypatch.setattr(index_engine.indexing, "_get_supported_input_files", discovery)

    assert list(index_engine.indexing.index_prepare_nodes_iter()) == []
    assert calls == ["embeddings", "discovery"]


def test_inventory_accepts_a_codebase_root_alias(index_engine, tmp_path, monkeypatch):
    (tmp_path / "source.py").write_text("value = 1\n", encoding="utf-8")
    alias = tmp_path.parent / f"{tmp_path.name}-alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setattr(index_engine._config, "codebase_path", str(alias))

    assert index_engine.indexing.count_index_items(input_files=["source.py"]) == 1
    list(index_engine.indexing.index_prepare_nodes_iter(input_files=["source.py"]))
    nodes, _docs = index_engine._state.pending_nodes
    assert nodes
    assert all(node.metadata["file_path"] == str(alias / "source.py") for node in nodes)


@pytest.mark.parametrize("duplicate", [False, True])
def test_inventory_rejects_noncanonical_case_spelling(inventory, tmp_path, duplicate):
    indexing, _selected, _prepared, embeddings = inventory
    alias = "SRC/PLAIN.PY"
    if not (tmp_path / alias).exists():
        pytest.skip("Filesystem uses case-sensitive names")
    selected = ["src/plain.py", alias] if duplicate else [alias]

    with pytest.raises(ValueError, match="spelling"):
        indexing.count_index_items(input_files=selected)
    with pytest.raises(ValueError, match="spelling"):
        list(indexing.index_prepare_nodes_iter(input_files=selected))

    embeddings.assert_not_called()


def test_distinct_hardlink_paths_are_separate_inputs(inventory, tmp_path):
    indexing, _selected, prepared, _embeddings = inventory
    (tmp_path / "src/hardlink.py").hardlink_to(tmp_path / "src/plain.py")
    selected = ["src/plain.py", "src/hardlink.py"]

    assert indexing.count_index_items(input_files=selected) == 2
    list(indexing.index_prepare_nodes_iter(input_files=selected))

    assert set(prepared) == {tmp_path / name for name in selected}
