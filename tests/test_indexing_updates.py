# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from unittest.mock import Mock

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
