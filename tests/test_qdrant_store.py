# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from contextlib import closing
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from llama_index.core.schema import TextNode
from llama_index.core.vector_stores.types import VectorStoreQuery
from qdrant_client import QdrantClient
from qdrant_client.models import Distance

from metis.vector_store import qdrant_store
from metis.vector_store.qdrant_store import QdrantStore


@pytest.fixture
def qdrant(monkeypatch):
    client = Mock()
    client.collection_exists.return_value = True
    client_constructor = Mock(return_value=client)
    stores = (object(), object())
    contexts = (object(), object())
    store_constructor = Mock(side_effect=stores)
    context_constructor = Mock(side_effect=contexts)

    monkeypatch.setattr(qdrant_store, "QdrantClient", client_constructor)
    monkeypatch.setattr(qdrant_store, "QdrantVectorStore", store_constructor)
    monkeypatch.setattr(
        qdrant_store.StorageContext,
        "from_defaults",
        context_constructor,
    )

    backend = QdrantStore(
        url="http://localhost:6333",
        api_key="secret",
        collection_prefix="project",
        embed_dim=8,
        embed_model_code=Mock(),
        embed_model_docs=Mock(),
    )
    return SimpleNamespace(
        backend=backend,
        client=client,
        client_constructor=client_constructor,
        stores=stores,
        contexts=contexts,
        context_constructor=context_constructor,
    )


def test_init_creates_collections_once(qdrant):
    qdrant.client.collection_exists.side_effect = [False, True]

    qdrant.backend.init()
    qdrant.backend.init()

    qdrant.client_constructor.assert_called_once_with(
        url="http://localhost:6333",
        api_key="secret",
    )
    create_kwargs = qdrant.client.create_collection.call_args.kwargs
    assert create_kwargs["collection_name"] == "project_code"
    assert create_kwargs["vectors_config"].size == 8
    assert create_kwargs["vectors_config"].distance == Distance.COSINE
    assert (
        qdrant.backend.vector_store_code,
        qdrant.backend.vector_store_docs,
    ) == qdrant.stores
    assert qdrant.backend.get_storage_contexts() == qdrant.contexts


def test_failed_init_does_not_publish_partial_state(qdrant):
    qdrant.client.close.side_effect = RuntimeError("close failure")
    qdrant.context_constructor.side_effect = RuntimeError("context failure")

    with pytest.raises(RuntimeError, match="context failure"):
        qdrant.backend.init()

    qdrant.client.close.assert_called_once_with()
    assert qdrant.backend._client is None
    assert not hasattr(qdrant.backend, "vector_store_code")
    assert not hasattr(qdrant.backend, "storage_context_code")


def test_local_client_indexes_queries_and_resets(monkeypatch):
    client = QdrantClient(location=":memory:")
    monkeypatch.setattr(qdrant_store, "QdrantClient", lambda **_kwargs: client)
    with closing(
        QdrantStore(
            url="http://unused.invalid",
            api_key=None,
            collection_prefix="project",
            embed_dim=3,
            embed_model_code=None,
            embed_model_docs=None,
        )
    ) as backend:
        backend.init()
        node = TextNode(
            id_="00000000-0000-0000-0000-000000000001",
            text="source evidence",
            embedding=[1.0, 0.0, 0.0],
        )
        backend.vector_store_code.add([node])
        query = VectorStoreQuery(query_embedding=node.embedding, similarity_top_k=1)
        assert backend.vector_store_code.query(query).ids == [node.node_id]
        backend.reset_index()
        assert backend.vector_store_code.query(query).ids == []
