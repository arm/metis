# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from abc import ABC
from abc import abstractmethod

from llama_index.core import VectorStoreIndex
from llama_index.core.indices.utils import embed_nodes
from llama_index.core.vector_stores import MetadataFilter
from llama_index.core.vector_stores import MetadataFilters

from metis.exceptions import RetrieverInitError
from metis.vector_store.retrievers import LlamaIndexNodeRetriever
from metis.vector_store.retrievers import QueryAnswerRetriever
from metis.vector_store.retrievers import query_chat_model_kwargs


class BaseVectorStore(ABC):
    @abstractmethod
    def init(self):
        """Initialize vector storage components (e.g., vector store and storage context)."""

    @abstractmethod
    def get_retrievers(
        self,
        llm_provider,
        similarity_top_k,
        callback_manager=None,
        callbacks=None,
    ):
        """Return tuple of LangChain-style retrievers (code, docs)."""

    @abstractmethod
    def index_nodes(
        self,
        nodes_code,
        nodes_docs,
        *,
        embed_model_code,
        embed_model_docs,
        **embed_model_kwargs,
    ):
        """Write prepared code and docs nodes to the vector backend."""

    @abstractmethod
    def get_index_handles(
        self,
        *,
        embed_model_code,
        embed_model_docs,
        **embed_model_kwargs,
    ):
        """Return mutable index handles (code, docs) for patch updates."""

    def replace_ref_doc(self, index, ref_doc_id, nodes, *, embed_model):
        """Replace one document without deleting its existing nodes first."""

        filters = MetadataFilters(
            filters=[MetadataFilter(key="ref_doc_id", value=ref_doc_id)]
        )
        old_nodes = index.vector_store.get_nodes(None, filters=filters)

        embeddings = embed_nodes(nodes, embed_model)
        embedded_nodes = []
        for node in nodes:
            embedded_node = node.model_copy()
            embedded_node.embedding = embeddings[node.node_id]
            embedded_nodes.append(embedded_node)

        index.insert_nodes(embedded_nodes)

        new_node_ids = {node.node_id for node in embedded_nodes}
        stale_node_ids = [
            node.node_id for node in old_nodes if node.node_id not in new_node_ids
        ]
        if stale_node_ids:
            index.vector_store.delete_nodes(node_ids=stale_node_ids)

    def close(self):
        """Best-effort resource cleanup hook for vector backends."""


class LlamaIndexVectorBackend(BaseVectorStore):
    """Shared behavior for backends exposed through LlamaIndex vector stores."""

    def get_retrievers(
        self,
        llm_provider,
        similarity_top_k,
        callback_manager=None,
        callbacks=None,
    ):
        try:
            indexes = self._index_handles(callback_manager=callback_manager)
            chat_model_kwargs = query_chat_model_kwargs(
                self.query_config,
                callbacks=callbacks,
            )
            return tuple(
                QueryAnswerRetriever(
                    LlamaIndexNodeRetriever(
                        index.as_retriever(similarity_top_k=similarity_top_k)
                    ),
                    llm_provider,
                    chat_model_kwargs=chat_model_kwargs,
                )
                for index in indexes
            )
        except Exception as exc:
            raise RetrieverInitError() from exc

    def index_nodes(
        self,
        nodes_code,
        nodes_docs,
        *,
        embed_model_code,
        embed_model_docs,
        **embed_model_kwargs,
    ):
        for nodes, storage_context, embed_model in zip(
            (nodes_code, nodes_docs),
            self.get_storage_contexts(),
            (embed_model_code, embed_model_docs),
            strict=True,
        ):
            VectorStoreIndex(
                nodes,
                storage_context=storage_context,
                embed_model=embed_model,
                **embed_model_kwargs,
            )

    def get_index_handles(
        self,
        *,
        embed_model_code,
        embed_model_docs,
        **embed_model_kwargs,
    ):
        return self._index_handles(
            embed_models=(embed_model_code, embed_model_docs),
            **embed_model_kwargs,
        )

    def _index_handles(
        self,
        *,
        embed_models=None,
        callback_manager=None,
        **embed_model_kwargs,
    ):
        embed_models = embed_models or (
            self.embed_model_code,
            self.embed_model_docs,
        )
        return tuple(
            VectorStoreIndex.from_vector_store(
                vector_store,
                storage_context=storage_context,
                embed_model=embed_model,
                callback_manager=callback_manager,
                **embed_model_kwargs,
            )
            for vector_store, storage_context, embed_model in zip(
                (self.vector_store_code, self.vector_store_docs),
                self.get_storage_contexts(),
                embed_models,
                strict=True,
            )
        )

    def get_storage_contexts(self):
        return self.storage_context_code, self.storage_context_docs
