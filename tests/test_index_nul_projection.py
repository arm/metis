# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from llama_index.core import VectorStoreIndex
from llama_index.core.embeddings import MockEmbedding
from llama_index.core.schema import Document
from llama_index.core.schema import IndexNode
from llama_index.core.schema import NodeRelationship
from llama_index.core.schema import RelatedNodeInfo
from llama_index.core.schema import TextNode
from metis.vector_store import llama_index_backend


@pytest.fixture
def index_call(monkeypatch: pytest.MonkeyPatch):
    write = Mock()
    monkeypatch.setattr(llama_index_backend, "VectorStoreIndex", write)
    backend = SimpleNamespace(get_storage_contexts=lambda: ("code-store", "docs-store"))
    return backend, write


@pytest.mark.parametrize("kind", ["code", "docs"])
def test_nul_projection_precedes_embedding_and_preserves_source_nodes(
    index_call,
    caplog: pytest.LogCaptureFixture,
    kind: str,
    tmp_path,
) -> None:
    backend, write = index_call
    # Read the entire node, including NUL after a long ordinary-text prefix.
    source = "x" * (65 * 1024) + "\x00sensitive-source\n"
    path = tmp_path / "source.py"
    path.write_text(source)
    node = TextNode(
        id_="node-stable",
        text=source,
        embedding=[0.1, 0.2, 0.3],
        metadata={"file_path": "source.py", "nested": {"key\x00": ["value\x00"]}},
        relationships={NodeRelationship.SOURCE: RelatedNodeInfo(node_id="doc-stable")},
    )
    original = node.model_dump()
    with caplog.at_level(logging.WARNING, logger="metis.vector_store.node_projection"):
        llama_index_backend.LlamaIndexVectorBackend.index_nodes(
            backend,
            [node] if kind == "code" else [],
            [node] if kind == "docs" else [],
            embed_model_code="code-model",
            embed_model_docs="docs-model",
            callback_manager="billing-hooks",
        )
    call = write.call_args_list[0 if kind == "code" else 1]
    projected = call.args[0][0]
    assert projected.text == source.replace("\x00", "\\u0000")
    assert projected.metadata["nested"] == {"key\\u0000": ["value\\u0000"]}
    assert projected.embedding is None
    assert projected.node_id == node.node_id
    assert projected.ref_doc_id == node.ref_doc_id
    assert node.model_dump() == original
    assert path.read_text() == source
    assert call.kwargs["callback_manager"] == "billing-hooks"
    assert call.kwargs["embed_model"] == f"{kind}-model"
    records = [
        r
        for r in caplog.records
        if getattr(r, "event", None) == "index_text_normalized"
    ]
    assert len(records) == 1
    assert records[0].nul_count == 3
    assert "source.py" in records[0].getMessage()
    assert "sensitive-source" not in caplog.text
    assert "value" not in caplog.text


def test_clean_nodes_keep_existing_embeddings_and_emit_no_normalization(
    index_call, caplog
):
    backend, write = index_call
    node = TextNode(id_="clean", text=r"literal \u0000 is not a NUL", embedding=[0.1])
    llama_index_backend.LlamaIndexVectorBackend.index_nodes(
        backend,
        [node],
        [],
        embed_model_code="code",
        embed_model_docs="docs",
    )
    assert write.call_args_list[0].args[0][0] is node
    assert not any(
        getattr(r, "event", None) == "index_text_normalized" for r in caplog.records
    )


@pytest.mark.parametrize("nul_field", ["text", "metadata"])
def test_normalized_index_reference_preserves_linked_source_retrieval(
    index_call, nul_field
):
    backend, write = index_call
    target = TextNode(
        id_="linked-source",
        text="original source passage",
        metadata={"file_path": "source.py", "start_line": 10, "end_line": 12},
    )
    reference = IndexNode(
        id_="reference",
        text="summary\x00text" if nul_field == "text" else "summary text",
        metadata={"summary": "reference\x00metadata"}
        if nul_field == "metadata"
        else {},
        index_id=target.node_id,
        obj=target,
        embedding=[0.1, 0.2, 0.3],
    )
    original = reference.model_dump()
    llama_index_backend.LlamaIndexVectorBackend.index_nodes(
        backend,
        [reference],
        [],
        embed_model_code="code",
        embed_model_docs="docs",
    )
    projected = write.call_args_list[0].args[0][0]
    assert isinstance(projected, IndexNode)
    assert isinstance(projected.obj, TextNode)
    assert projected.embedding is None
    assert projected.node_id == reference.node_id
    assert projected.index_id == target.node_id
    assert reference.model_dump() == original

    index = VectorStoreIndex([projected], embed_model=MockEmbedding(embed_dim=3))
    (retrieved,) = index.as_retriever(similarity_top_k=1).retrieve("source passage")
    assert retrieved.node.get_content() == target.get_content()
    assert retrieved.node.node_id == target.node_id
    assert retrieved.node.metadata == target.metadata


@pytest.mark.parametrize("identity", ["node", "source", "child", "index"])
def test_invalid_identity_fails_before_either_collection_is_embedded(
    index_call, identity
):
    backend, write = index_call
    node = TextNode(id_="ok", text="docs")
    if identity == "node":
        node.id_ = "bad\x00id"
    elif identity == "index":
        node = IndexNode(text="docs", index_id="bad\x00id")
    else:
        relation = (
            NodeRelationship.SOURCE if identity == "source" else NodeRelationship.CHILD
        )
        info = RelatedNodeInfo(node_id="bad\x00id")
        node.relationships[relation] = info if identity == "source" else [info]
    with pytest.raises(ValueError, match="NUL in index node identity"):
        llama_index_backend.LlamaIndexVectorBackend.index_nodes(
            backend,
            [TextNode(text="valid code")],
            [node],
            embed_model_code="code",
            embed_model_docs="docs",
        )
    write.assert_not_called()


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("linked", [False, True])
def test_metadata_key_collisions_fail_without_dropping_data(
    index_call, reverse, linked
):
    backend, write = index_call
    items = [("key\x00", "first"), ("key\\u0000", "second")]
    node = TextNode(text="docs", metadata=dict(reversed(items) if reverse else items))
    if linked:
        node = IndexNode(text="summary", index_id=node.node_id, obj=node)
    original = node.model_dump()
    with pytest.raises(ValueError, match="merge index metadata keys"):
        llama_index_backend.LlamaIndexVectorBackend.index_nodes(
            backend,
            [],
            [node],
            embed_model_code="code",
            embed_model_docs="docs",
        )
    write.assert_not_called()
    assert node.model_dump() == original


def test_projection_is_idempotent_and_keeps_recomputed_embedding(index_call):
    backend, write = index_call
    llama_index_backend.LlamaIndexVectorBackend.index_nodes(
        backend,
        [TextNode(text="a\x00b")],
        [],
        embed_model_code="code",
        embed_model_docs="docs",
    )
    projected = write.call_args_list[0].args[0][0]
    projected.embedding = [0.1]
    write.reset_mock()
    llama_index_backend.LlamaIndexVectorBackend.index_nodes(
        backend,
        [projected],
        [],
        embed_model_code="code",
        embed_model_docs="docs",
    )
    assert write.call_args_list[0].args[0][0] is projected
    assert projected.embedding == [0.1]


def test_full_build_normalizes_reader_output_without_changing_source(
    engine, dummy_backend
):
    path = Path(engine._config.codebase_path) / "nul.md"
    path.write_text("before\x00after", encoding="utf-8")
    engine.indexing.index_codebase()

    _, docs = dummy_backend.index_nodes.call_args.args
    node = next(node for node in docs if node.ref_doc_id.endswith("/nul.md"))
    assert node.text == "before\\u0000after"
    assert path.read_text(encoding="utf-8") == "before\x00after"


@pytest.mark.parametrize("invalid", ["identity", "collision"])
def test_full_build_preflights_both_collections_before_reset(
    engine, dummy_backend, invalid
):
    node = TextNode(text="documentation")
    if invalid == "identity":
        node.id_ = "invalid\x00id"
    else:
        node.metadata = {"key\x00": "one", r"key\u0000": "two"}
    engine._state.pending_nodes = ([TextNode(text="valid code")], [node])

    with pytest.raises(ValueError, match="NUL"):
        engine.indexing.index_finalize_embeddings()

    dummy_backend.init.assert_not_called()
    dummy_backend.reset_index.assert_not_called()
    dummy_backend.index_nodes.assert_not_called()
    assert engine._state.pending_nodes is None


@pytest.mark.parametrize("added", [False, True])
def test_incremental_updates_normalize_before_writing(engine, dummy_backend, added):
    path = Path(engine._config.codebase_path) / "nul.md"
    path.write_text("before\x00after\n", encoding="utf-8")
    patch = (
        "--- /dev/null\n+++ b/nul.md\n@@ -0,0 +1 @@\n+new\n"
        if added
        else "--- a/nul.md\n+++ b/nul.md\n@@ -1 +1 @@\n-old\n+new\n"
    )
    target = dummy_backend.get_index_handles.return_value[1]
    engine.indexing.update_index(patch)

    if added:
        (node,) = target.insert_nodes.call_args.args[0]
    else:
        (node,) = target.update_ref_doc.call_args.args
    assert "\x00" not in node.get_content()
    assert r"before\u0000after" in node.get_content()
    assert path.read_text(encoding="utf-8") == "before\x00after\n"


@pytest.mark.parametrize("invalid", ["identity", "collision"])
def test_invalid_incremental_document_is_rejected_before_replacement(
    engine, dummy_backend, monkeypatch, invalid
):
    path = Path(engine._config.codebase_path) / "nul.md"
    path.write_text("new", encoding="utf-8")
    doc = Document(id_="stable", text="new")
    if invalid == "identity":
        doc.id_ = "bad\x00id"
    else:
        doc.metadata = {"key\x00": "one", r"key\u0000": "two"}
    monkeypatch.setattr(
        "metis.engine.capabilities.indexing.Document", Mock(return_value=doc)
    )
    target = dummy_backend.get_index_handles.return_value[1]
    patch = "--- a/nul.md\n+++ b/nul.md\n@@ -1 +1 @@\n-old\n+new\n"

    with pytest.raises(ValueError, match="NUL"):
        engine.indexing.update_index(patch)

    target.update_ref_doc.assert_not_called()
    target.delete_ref_doc.assert_not_called()
    target.insert_nodes.assert_not_called()
    target.docstore.set_document_hash.assert_not_called()


def test_chroma_normalization_and_rejected_rebuild_preserve_stored_data(
    engine, tmp_path
):
    from llama_index.core.embeddings import MockEmbedding

    from metis.engine.capabilities.indexing import IndexingService
    from metis.engine.runtime import EngineState
    from metis.vector_store.chroma_store import ChromaStore

    embed = MockEmbedding(embed_dim=3)
    backend = ChromaStore(str(tmp_path / "chroma"), embed, embed, {})
    state = EngineState()
    indexing = IndexingService(
        replace(engine._config, vector_backend=backend),
        state,
        engine.repository,
        get_embedding_models=lambda: (embed, embed),
    )
    try:
        backend.init()
        backend.index_nodes(
            [TextNode(id_="clean", text="clean code")],
            [TextNode(id_="previous", text="before\x00after")],
            embed_model_code=embed,
            embed_model_docs=embed,
        )
        before = backend.collection_docs.get()
        assert before["ids"] == ["previous"]
        assert before["documents"] == [r"before\u0000after"]
        state.pending_nodes = (
            [TextNode(text="new code")],
            [
                TextNode(
                    text="new docs", metadata={"key\x00": "one", r"key\u0000": "two"}
                )
            ],
        )

        with pytest.raises(ValueError, match="NUL normalization would merge"):
            indexing.index_finalize_embeddings()

        assert backend.collection_code.get()["ids"] == ["clean"]
        assert backend.collection_docs.get() == before
    finally:
        backend.close()
