# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from contextlib import closing
from pathlib import Path

from fsspec.implementations.local import LocalFileSystem
from llama_index.core import SimpleDirectoryReader
from llama_index.core.schema import Document
import pytest

from metis.engine import MetisEngine


@pytest.fixture
def index_engine(
    tmp_path, dummy_backend, dummy_llm, dummy_embedding_provider, capability_settings
):
    with closing(
        MetisEngine(
            codebase_path=str(tmp_path),
            vector_backend=dummy_backend,
            llm_provider=dummy_llm,
            embedding_provider=dummy_embedding_provider,
            capability_settings=capability_settings,
            max_workers=2,
            max_token_length=2048,
            llama_query_model="inert-test",
            similarity_top_k=3,
        )
    ) as engine:
        yield engine


def test_index_reader_never_opens_ignored_files(index_engine, tmp_path, monkeypatch):
    (tmp_path / "keep.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "drop.py").write_text("value = 2\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("drop.py\n", encoding="utf-8")
    real_open = LocalFileSystem.open
    opened = []
    prepared = []

    def checked_open(self, path, *args, **kwargs):
        opened.append(Path(path).name)
        if Path(path).name == "drop.py":
            raise PermissionError("Ignored files must not be opened")
        return real_open(self, path, *args, **kwargs)

    def prepare(code_docs, doc_docs, *_args):
        prepared.extend(Path(doc.id_).name for doc in [*code_docs, *doc_docs])
        yield None
        return [], []

    monkeypatch.setattr(LocalFileSystem, "open", checked_open)
    monkeypatch.setattr(
        "metis.engine.capabilities.indexing.prepare_nodes_iter", prepare
    )
    index_engine.indexing.index_prepare_nodes()

    assert opened == ["keep.py"]
    assert prepared == ["keep.py"]


@pytest.mark.parametrize("all_ignored", [False, True])
def test_empty_index_selection_finishes_without_a_reader(
    index_engine, tmp_path, monkeypatch, dummy_backend, all_ignored
):
    if all_ignored:
        (tmp_path / "drop.py").write_text("value = 1\n", encoding="utf-8")
        (tmp_path / ".metisignore").write_text("*\n", encoding="utf-8")

    def unexpected_reader(**_kwargs):
        pytest.fail("An empty selection must not construct a file reader")

    monkeypatch.setattr(
        "metis.engine.capabilities.indexing.SimpleDirectoryReader", unexpected_reader
    )
    assert index_engine.indexing.count_index_items() == 0
    assert list(index_engine.indexing.index_prepare_nodes_iter()) == []
    assert index_engine._state.pending_nodes == ([], [])
    index_engine.indexing.index_finalize_embeddings()
    assert index_engine._state.pending_nodes is None
    assert dummy_backend.index_nodes.call_args.args == ([], [])


def test_index_count_ignores_review_filters(index_engine, tmp_path):
    for name in ("keep.py", "other.py", "ignored.py", "README.md"):
        (tmp_path / name).write_text("inert text\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("ignored.py\n", encoding="utf-8")
    index_engine._config.review_code_include_paths = ["keep.py"]
    index_engine._config.review_code_exclude_paths = ["other.py"]

    assert len(index_engine.repository.get_code_files()) == 1
    assert index_engine.indexing.count_index_items() == 3


def test_multipart_documents_keep_origin_and_unique_ids(
    index_engine, tmp_path, monkeypatch
):
    class MultipartReader:
        def load_data(self, file, extra_info):
            return [
                Document(text="page one", metadata=extra_info),
                Document(text="page two", metadata=extra_info),
            ]

    monkeypatch.setattr(
        SimpleDirectoryReader,
        "supported_suffix_fn",
        staticmethod(lambda: {".md": MultipartReader}),
    )
    (tmp_path / "input.md").write_text("inert text\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("*\n!input.md\n", encoding="utf-8")
    index_engine.indexing.index_prepare_nodes()

    code_nodes, doc_nodes = index_engine._state.pending_nodes
    assert code_nodes == []
    assert [node.text for node in doc_nodes] == ["page one", "page two"]
    assert [node.ref_doc_id for node in doc_nodes] == [
        f"{tmp_path.name}/input.md_part_0",
        f"{tmp_path.name}/input.md_part_1",
    ]
    assert all(
        node.metadata["file_path"] == str(tmp_path / "input.md") for node in doc_nodes
    )


def test_configured_document_extensions_are_case_insensitive(index_engine, tmp_path):
    index_engine._config.plugin_config["docs"]["supported_extensions"] = [".MD"]
    (tmp_path / "input.MD").write_text("retained text\n", encoding="utf-8")

    assert index_engine.indexing.count_index_items() == 1
    index_engine.indexing.index_prepare_nodes()
    code_nodes, doc_nodes = index_engine._state.pending_nodes
    assert code_nodes == []
    assert [node.text for node in doc_nodes] == ["retained text"]
