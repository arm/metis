# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import Any

from langchain_core.documents import Document
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.chat_model_options import merge_chat_model_kwargs


def retriever_query_config(runtime: dict[str, Any]) -> dict[str, Any]:
    return {
        "llama_query_model": runtime.get("llama_query_model"),
        "chat_model_kwargs": dict(runtime.get("chat_model_kwargs") or {}),
        "similarity_top_k": runtime.get("similarity_top_k", 5),
    }


def query_chat_model_kwargs(
    query_config: dict[str, Any], *, callbacks: Any = None
) -> dict[str, Any]:
    return merge_chat_model_kwargs(
        query_config.get("chat_model_kwargs") or {},
        model=query_config.get("llama_query_model"),
        callbacks=callbacks,
    )


class QueryAnswerRetriever:
    def __init__(
        self,
        retriever: Any,
        llm_provider: Any,
        *,
        chat_model_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self._retriever = retriever
        self._llm_provider = llm_provider
        self._chat_model_kwargs = dict(chat_model_kwargs or {})

    def get_relevant_documents(self, query: str) -> list[Document]:
        answer = self._query_text(query)
        return [Document(page_content=answer)] if answer else []

    def invoke(self, query: str) -> list[Document]:
        return self.get_relevant_documents(query)

    def _query_text(self, query: str) -> str:
        context = self._retrieve_context(query)
        if not context.strip():
            return ""
        chat = self._llm_provider.get_chat_model(**self._chat_model_kwargs)
        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "You synthesize retrieval results for downstream codebase "
                    "questions and security review prompts. Use only the retrieved "
                    "context. Preserve concrete names, files, APIs, behavior, and "
                    "security-relevant facts. If the context is incomplete, include "
                    "the relevant facts that are present and state only the specific "
                    "gap.",
                ),
                (
                    "user",
                    "Request:\n{query}\n\nRetrieved context:\n{context}\n\n"
                    "Synthesize the relevant answer or context.",
                ),
            ]
        )
        return (
            (prompt | chat | StrOutputParser())
            .invoke({"query": query, "context": context})
            .strip()
        )

    def _retrieve_context(self, query: str) -> str:
        documents = retrieve_documents(self._retriever, query)
        return "\n\n".join(
            text for document in (documents or []) if (text := document_text(document))
        )


class ChromaCollectionRetriever:
    def __init__(self, collection: Any, embed_model: Any, *, k: int):
        self._collection = collection
        self._embed_model = embed_model
        self._k = k

    def get_relevant_documents(self, query: str) -> list[Document]:
        embedding = _embed_query(self._embed_model, query)
        result = self._collection.query(
            query_embeddings=[embedding],
            n_results=self._k,
            include=["documents", "metadatas"],
        )
        documents = _first_result_list(result.get("documents"))
        metadatas = _first_result_list(result.get("metadatas"))
        out: list[Document] = []
        row_count = max(len(documents), len(metadatas))
        for idx in range(row_count):
            raw_text = documents[idx] if idx < len(documents) else ""
            metadata = metadatas[idx] if idx < len(metadatas) else {}
            text = document_text(raw_text) or document_text(metadata)
            if not text:
                continue
            out.append(
                Document(
                    page_content=text,
                    metadata=metadata if isinstance(metadata, dict) else {},
                )
            )
        return out

    def invoke(self, query: str) -> list[Document]:
        return self.get_relevant_documents(query)


class LlamaIndexNodeRetriever:
    def __init__(self, retriever: Any):
        self._retriever = retriever

    def get_relevant_documents(self, query: str) -> list[Document]:
        nodes = self._retriever.retrieve(query)
        return [_document_from_node(node) for node in nodes or []]

    def invoke(self, query: str) -> list[Document]:
        return self.get_relevant_documents(query)


def document_text(document: Any) -> str:
    if document is None:
        return ""
    if isinstance(document, str):
        return document

    page_content = getattr(document, "page_content", None)
    if page_content is not None:
        return str(page_content)

    source = getattr(document, "node", document)
    get_content = getattr(source, "get_content", None)
    if callable(get_content):
        return str(get_content())

    text = getattr(source, "text", None)
    if text is not None:
        return str(text)

    if isinstance(source, dict):
        for key in ("page_content", "text", "document"):
            if source.get(key) is not None:
                return str(source[key])
        node_content = source.get("_node_content")
        if node_content is not None:
            return _node_content_text(node_content)

    return ""


def retrieve_documents(retriever: Any, query: str):
    get_relevant_documents = getattr(retriever, "get_relevant_documents", None)
    if callable(get_relevant_documents):
        return get_relevant_documents(query)
    invoke = getattr(retriever, "invoke", None)
    if callable(invoke):
        return invoke(query)
    retrieve = getattr(retriever, "retrieve", None)
    if callable(retrieve):
        return retrieve(query)
    return []


def _node_content_text(node_content: Any) -> str:
    if isinstance(node_content, str):
        try:
            payload = json.loads(node_content)
        except json.JSONDecodeError:
            return node_content
    elif isinstance(node_content, dict):
        payload = node_content
    else:
        return ""

    if not isinstance(payload, dict):
        return ""

    for key in ("text", "text_resource", "page_content", "document"):
        value = payload.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            nested = document_text(value)
            if nested:
                return nested

    return ""


def _embed_query(embed_model: Any, query: str) -> list[float]:
    get_query_embedding = getattr(embed_model, "get_query_embedding", None)
    if callable(get_query_embedding):
        return list(get_query_embedding(query))
    embed_query = getattr(embed_model, "embed_query", None)
    if callable(embed_query):
        return list(embed_query(query))
    raise TypeError("Embedding model does not support query embeddings.")


def _first_result_list(value: Any) -> list[Any]:
    if not value:
        return []
    if isinstance(value, list) and value and isinstance(value[0], list):
        return list(value[0])
    if isinstance(value, list):
        return list(value)
    return []


def _document_from_node(node: Any) -> Document:
    source = getattr(node, "node", node)
    metadata = getattr(source, "metadata", None)
    return Document(
        page_content=document_text(source),
        metadata=metadata if isinstance(metadata, dict) else {},
    )
