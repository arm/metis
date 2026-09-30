# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from unittest.mock import Mock

import pytest
from llama_index.core import VectorStoreIndex
from llama_index.core.embeddings.mock_embed_model import MockEmbedding
from llama_index.core.schema import Document
from llama_index.core.vector_stores.simple import SimpleVectorStore


def test_modified_patch_replaces_vectors_with_fresh_index_handles(
    engine, dummy_backend
):
    embed = MockEmbedding(embed_dim=8)
    store = SimpleVectorStore()
    store.stores_text = True
    codebase = Path(engine._config.codebase_path)
    doc_id = f"{codebase.name}/update.c"
    original_index = VectorStoreIndex.from_vector_store(store, embed_model=embed)
    original_index.insert(Document(text="int before;", id_=doc_id))
    original_index.insert(Document(text="int untouched;", id_="untouched"))
    original_nodes = set(store.data.embedding_dict)

    updated_index = VectorStoreIndex.from_vector_store(store, embed_model=embed)
    assert updated_index.docstore.get_document_hash(doc_id) is None
    dummy_backend.get_index_handles.return_value = (updated_index, Mock())
    (codebase / "update.c").write_text("int after;", encoding="utf-8")
    engine.indexing.update_index(
        "--- a/update.c\n+++ b/update.c\n@@ -1 +1 @@\n-int before;\n+int after;\n"
    )
    references = store.data.text_id_to_ref_doc_id
    assert sorted(references.values()) == sorted([doc_id, "untouched"])
    assert len(original_nodes & references.keys()) == 1


class _Indexes:
    """In-memory code and docs indexes plus the codebase directory they cover."""

    def __init__(self, engine, dummy_backend):
        self.code_store, self.docs_store = SimpleVectorStore(), SimpleVectorStore()
        embed = MockEmbedding(embed_dim=8)
        for store in (self.code_store, self.docs_store):
            store.stores_text = True
        self.code_index, self.docs_index = (
            VectorStoreIndex.from_vector_store(store, embed_model=embed)
            for store in (self.code_store, self.docs_store)
        )
        dummy_backend.get_index_handles.return_value = (
            self.code_index,
            self.docs_index,
        )
        self.codebase = Path(engine._config.codebase_path)

    def seed(self, name, text="int old;"):
        doc = Document(text=text, id_=f"{self.codebase.name}/{name}")
        self.code_index.insert(doc)

    def write(self, name, text="int new;\n"):
        (self.codebase / name).write_text(text, encoding="utf-8")

    def _names(self, store):
        refs = store.data.text_id_to_ref_doc_id.values()
        return {ref.removeprefix(f"{self.codebase.name}/") for ref in refs}

    def code_rows(self):
        return self._names(self.code_store)

    def docs_rows(self):
        return self._names(self.docs_store)


@pytest.fixture
def idx(engine, dummy_backend):
    return _Indexes(engine, dummy_backend)


def _rename_patch(old, new, *, similarity=100, edit=False, prefix=True):
    a, b = ("a/", "b/") if prefix else ("", "")
    patch_text = (
        f"diff --git {a}{old} {b}{new}\n"
        f"similarity index {similarity}%\n"
        f"rename from {old}\n"
        f"rename to {new}\n"
    )
    if edit:
        patch_text += (
            f"--- {a}{old}\n+++ {b}{new}\n@@ -1 +1,2 @@\n int before;\n+int after;\n"
        )
    return patch_text


@pytest.mark.parametrize(
    ("similarity", "edit", "prefix"),
    [(100, False, True), (90, True, True), (100, False, False)],
    ids=["pure", "edited", "no-prefix"],
)
def test_renamed_file_replaces_old_path_with_new_path(
    engine, idx, similarity, edit, prefix
):
    idx.seed("old.c", "int before;")
    idx.seed("untouched.c")
    idx.write("new.c", "int before;\nint after;\n")

    engine.indexing.update_index(
        _rename_patch("old.c", "new.c", similarity=similarity, edit=edit, prefix=prefix)
    )

    assert idx.code_rows() == {"new.c", "untouched.c"}


def test_rename_between_code_and_docs_moves_the_rows_between_indexes(engine, idx):
    idx.seed("notes.c")
    idx.write("notes.md", "# notes\n")

    engine.indexing.update_index(_rename_patch("notes.c", "notes.md"))

    assert idx.code_rows() == set()
    assert idx.docs_rows() == {"notes.md"}


def test_rename_of_a_path_that_was_never_indexed_still_adds_the_new_path(engine, idx):
    idx.write("new.c")

    engine.indexing.update_index(_rename_patch("gone.c", "new.c"))

    assert idx.code_rows() == {"new.c"}


@pytest.mark.parametrize(
    ("patch_text", "seeded", "written", "expected"),
    [
        pytest.param(
            'diff --git "a/caf\\303\\251.c" "b/caf\\303\\251.c"\n'
            '--- "a/caf\\303\\251.c"\n+++ "b/caf\\303\\251.c"\n'
            "@@ -1 +1 @@\n-int before;\n+int after;\n",
            None,
            "café.c",
            {"café.c"},
            id="modify",
        ),
        pytest.param(
            'diff --git "a/caf\\303\\251.c" "b/caf\\303\\251.c"\n'
            'deleted file mode 100644\n--- "a/caf\\303\\251.c"\n+++ /dev/null\n'
            "@@ -1 +0,0 @@\n-int before;\n",
            "café.c",
            None,
            set(),
            id="delete",
        ),
        pytest.param(
            'diff --git "a/caf\\303\\251.c" "b/na\\303\\257ve.c"\n'
            'similarity index 100%\nrename from "caf\\303\\251.c"\n'
            'rename to "na\\303\\257ve.c"\n',
            "café.c",
            "naïve.c",
            {"naïve.c"},
            id="rename",
        ),
    ],
)
def test_update_decodes_git_quoted_paths(
    engine, idx, patch_text, seeded, written, expected
):
    if seeded:
        idx.seed(seeded)
    if written:
        idx.write(written)

    engine.indexing.update_index(patch_text)

    assert idx.code_rows() == expected


def _modify_patch(name):
    return f"--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n-old\n+new\n"


@pytest.mark.parametrize("seeded", [False, True], ids=["new-file", "already-indexed"])
def test_update_drops_a_file_the_index_rules_ignore(engine, idx, seeded):
    if seeded:
        idx.seed("generated/out.c")
    idx.write(".metisignore", "generated/\n")
    (idx.codebase / "generated").mkdir()
    idx.write("generated/out.c")
    idx.write("kept.c")

    engine.indexing.update_index(
        _modify_patch("generated/out.c") + _modify_patch("kept.c")
    )

    assert idx.code_rows() == {"kept.c"}
    assert idx.docs_rows() == set()


@pytest.mark.parametrize("name", ["data.json", "notes.yaml", "unknown.bin"])
def test_update_skips_unsupported_files(engine, idx, name):
    idx.write(name)

    engine.indexing.update_index(_modify_patch(name))

    assert idx.code_rows() == idx.docs_rows() == set()


def test_update_keeps_documentation_in_docs_index(engine, idx):
    idx.write("guide.md", "# Guide\n")

    engine.indexing.update_index(_modify_patch("guide.md"))

    assert idx.code_rows() == set()
    assert idx.docs_rows() == {"guide.md"}


def test_update_deletes_a_removed_selected_file(engine, idx):
    idx.seed("gone.c")

    engine.indexing.update_index(
        "--- a/gone.c\n+++ /dev/null\n@@ -1 +0,0 @@\n-int old;\n"
        "--- a/data.json\n+++ /dev/null\n@@ -1 +0,0 @@\n-{}\n"
    )

    assert idx.code_rows() == set()
