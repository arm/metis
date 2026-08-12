# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.core import VectorStoreIndex

from metis.exceptions import RetrieverInitError
from metis.vector_store.base import BaseVectorStore
from metis.vector_store.retrievers import LlamaIndexNodeRetriever
from metis.vector_store.retrievers import QueryAnswerRetriever
from metis.vector_store.retrievers import query_chat_model_kwargs


class LlamaIndexVectorBackend(BaseVectorStore):
    """Shared behavior for backends exposed through LlamaIndex vector stores."""

    index_class = VectorStoreIndex

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
            self.index_class(
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
            self.index_class.from_vector_store(
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
