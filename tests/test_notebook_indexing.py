# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path
import sys

import pytest
from llama_index.core import SimpleDirectoryReader
from llama_index.core.schema import Document

from test_indexing_selection import index_engine as index_engine


@pytest.fixture
def notebook_index(index_engine, tmp_path):
    def index(metadata, execution_count=None, sources=None, invalid_byte=False):
        sources = (
            sources
            if sources is not None
            else [
                "raise RuntimeError('notebook cells must not execute')\nfirst_cell = 41\n",
                "second_cell = first_cell + 1\nliteral_template = '{{ 6 * 7 }}'\n",
            ]
        )
        target = tmp_path / "source.ipynb"
        target.write_text(
            json.dumps(
                {
                    "nbformat": 4,
                    "nbformat_minor": 5,
                    "metadata": metadata,
                    "cells": [
                        {
                            "id": f"cell-{number}",
                            "cell_type": "code",
                            "metadata": {},
                            "execution_count": execution_count,
                            "outputs": [
                                {
                                    "output_type": "stream",
                                    "name": "stdout",
                                    "text": "cell_output_must_not_be_indexed",
                                }
                            ],
                            "source": source,
                        }
                        for number, source in enumerate(sources)
                    ]
                    + [
                        {
                            "id": "markdown",
                            "cell_type": "markdown",
                            "metadata": {},
                            "source": "markdown_must_not_be_indexed_as_code",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        if invalid_byte:
            target.write_bytes(
                target.read_bytes().replace(b"first_cell", b"\xfffirst_cell", 1)
            )
        index_engine.indexing.index_prepare_nodes()

        nodes, _docs = index_engine._state.pending_nodes
        assert nodes
        text = "\n".join(node.text for node in nodes)
        assert all(source.strip() in text for source in sources)
        assert all(f"# Cell {number + 1}" in text for number in range(len(sources)))
        assert "cell_output_must_not_be_indexed" not in text
        assert "markdown_must_not_be_indexed_as_code" not in text
        assert all(Path(node.metadata["file_path"]) == target for node in nodes)
        assert all(node.ref_doc_id == f"{tmp_path.name}/source.ipynb" for node in nodes)

    return index


@pytest.mark.parametrize("execution_count", [None, 7])
@pytest.mark.parametrize(
    "language_info",
    [
        None,
        {"name": "python", "nbconvert_exporter": "python"},
        {"name": "python", "nbconvert_exporter": "must-not-load"},
    ],
)
def test_index_retains_complete_static_notebook_source(
    notebook_index, execution_count, language_info
):
    metadata = {"language_info": language_info} if language_info is not None else {}
    notebook_index(metadata, execution_count)


@pytest.mark.parametrize(
    "source", ["[1, 2, 3]", '{"threshold": 3}', '"text"', "7", "null"]
)
def test_json_looking_cells_survive_the_real_notebook_splitter(notebook_index, source):
    notebook_index({}, sources=[source])


@pytest.mark.parametrize("execution_count", [None, 7])
def test_optional_notebook_reader_cannot_replace_static_extraction(
    notebook_index, monkeypatch, execution_count
):
    calls = []

    class UnexpectedNotebookReader:
        def load_data(self, *_args, **_kwargs):
            calls.append(True)
            raise RuntimeError("Optional reader must not convert notebooks")

    monkeypatch.setattr(
        SimpleDirectoryReader,
        "supported_suffix_fn",
        staticmethod(lambda: {".ipynb": UnexpectedNotebookReader}),
    )

    notebook_index(
        {"language_info": {"nbconvert_exporter": "must-not-load"}}, execution_count
    )
    assert calls == []


def test_notebook_indexing_does_not_require_nbconvert(notebook_index, monkeypatch):
    monkeypatch.setitem(sys.modules, "nbconvert", None)
    monkeypatch.setitem(sys.modules, "nbconvert.exporters", None)

    notebook_index({"language_info": {"nbconvert_exporter": "must-not-load"}})


def test_notebook_preserves_native_lenient_source_decoding(notebook_index):
    notebook_index({}, invalid_byte=True)


def test_unreadable_notebook_fails_indexing(index_engine, tmp_path, monkeypatch):
    (tmp_path / "source.ipynb").write_text("{}", encoding="utf-8")
    failure = PermissionError("notebook unavailable")
    read_text = Path.read_text

    def checked_read_text(self, *args, **kwargs):
        if self.suffix == ".ipynb":
            raise failure
        return read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", checked_read_text)

    with pytest.raises(PermissionError) as raised:
        index_engine.indexing.index_prepare_nodes()

    assert raised.value is failure
    assert index_engine._state.pending_nodes is None


def test_reader_document_ids_do_not_change_source_language(
    index_engine, tmp_path, monkeypatch
):
    class MultipartCodeReader:
        def load_data(self, file, extra_info):
            return [Document(text="value = 1\n", metadata=extra_info)]

    (tmp_path / "source.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        SimpleDirectoryReader,
        "supported_suffix_fn",
        staticmethod(lambda: {".py": MultipartCodeReader}),
    )

    index_engine.indexing.index_prepare_nodes()

    nodes, _docs = index_engine._state.pending_nodes
    assert nodes
    assert "value = 1" in "\n".join(node.text for node in nodes)


def test_notebook_ignores_workspace_templates(notebook_index, tmp_path, monkeypatch):
    template = tmp_path / "script"
    template.mkdir()
    (template / "conf.json").write_text("invalid configuration", encoding="utf-8")
    (template / "script.j2").write_text("untrusted template", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    notebook_index({"language_info": {"name": "python"}})
