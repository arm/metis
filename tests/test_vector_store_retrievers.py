# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from langchain_core.documents import Document
from langchain_core.runnables import RunnableLambda

from metis.vector_store.retrievers import ChromaCollectionRetriever
from metis.vector_store.retrievers import QueryAnswerRetriever


class _FakeProvider:
    def __init__(self):
        self.kwargs = None

    def get_chat_model(self, **kwargs):
        self.kwargs = kwargs
        return RunnableLambda(lambda _prompt: "synthesized answer")


def test_query_answer_retriever_returns_synthesized_single_document():
    class _RawRetriever:
        def get_relevant_documents(self, query):
            assert query == "what is this?"
            return [
                Document(page_content="chunk one"),
                Document(page_content="chunk two"),
            ]

    provider = _FakeProvider()
    retriever = QueryAnswerRetriever(
        _RawRetriever(),
        provider,
        chat_model_kwargs={"callbacks": ["cb"]},
    )

    docs = retriever.get_relevant_documents("what is this?")

    assert [doc.page_content for doc in docs] == ["synthesized answer"]
    assert provider.kwargs == {"callbacks": ["cb"]}


def test_query_answer_retriever_returns_no_document_without_context():
    class _RawRetriever:
        def get_relevant_documents(self, _query):
            return []

    retriever = QueryAnswerRetriever(_RawRetriever(), _FakeProvider())

    assert retriever.get_relevant_documents("missing") == []


def test_chroma_collection_retriever_queries_collection_with_embedding():
    class _Embedding:
        def get_query_embedding(self, query):
            assert query == "lookup"
            return [1.0, 2.0]

    class _Collection:
        def __init__(self):
            self.query_kwargs = None

        def query(self, **kwargs):
            self.query_kwargs = kwargs
            return {
                "documents": [["code chunk"]],
                "metadatas": [[{"file_name": "a.py"}]],
            }

    collection = _Collection()
    retriever = ChromaCollectionRetriever(collection, _Embedding(), k=3)

    docs = retriever.get_relevant_documents("lookup")

    assert docs == [Document(page_content="code chunk", metadata={"file_name": "a.py"})]
    assert collection.query_kwargs == {
        "query_embeddings": [[1.0, 2.0]],
        "n_results": 3,
        "include": ["documents", "metadatas"],
    }
