# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import asyncio
from typing import Any, cast
from unittest.mock import Mock

import pytest

from langchain_core.embeddings import Embeddings
from langchain_openai import ChatOpenAI

from metis.providers.embedding_adapter import LangChainEmbeddingAdapter
from metis.providers.llamacpp import LlamaCppEmbeddingProvider
from metis.providers.ollama import OllamaEmbeddingProvider
from metis.providers.vllm import VLLMProvider, VLLMEmbeddingProvider
from metis.providers.openai_compatible import OpenAICompatibleChatConfig
from metis.providers.openai_compatible import OpenAICompatibleChatProvider
from metis.providers.openai_compatible import OpenAICompatibleEmbeddingConfig
from metis.providers.openai_compatible import OpenAICompatibleEmbeddingProvider


def _chat_config(**overrides: object) -> OpenAICompatibleChatConfig:
    config: dict[str, object] = {
        "api_key": "test-key",
        "model": "gpt-test",
    }
    config.update(overrides)
    return cast(OpenAICompatibleChatConfig, config)


def _embedding_config(**overrides: object) -> OpenAICompatibleEmbeddingConfig:
    config: dict[str, object] = {
        "api_key": "test-key",
        "code_embedding_model": "text-embedding-3-large",
        "docs_embedding_model": "text-embedding-3-small",
    }
    config.update(overrides)
    return cast(OpenAICompatibleEmbeddingConfig, config)


def test_chat_model_forwards_supported_runtime_options() -> None:
    provider = OpenAICompatibleChatProvider(_chat_config())

    llm = provider.get_chat_model(reasoning_effort="high", max_tokens=256)

    assert isinstance(llm, ChatOpenAI)
    assert llm.reasoning_effort == "high"
    assert llm.max_tokens == 256
    assert llm.use_responses_api is True


def test_chat_model_applies_configured_max_retries() -> None:
    provider = OpenAICompatibleChatProvider(_chat_config(max_retries=7))

    llm = provider.get_chat_model()

    assert llm.max_retries == 7


def test_chat_model_caller_can_override_max_retries() -> None:
    provider = OpenAICompatibleChatProvider(_chat_config(max_retries=7))

    llm = provider.get_chat_model(max_retries=1)

    assert llm.max_retries == 1


def test_chat_model_default_max_retries() -> None:
    provider = OpenAICompatibleChatProvider(_chat_config())

    llm = provider.get_chat_model()

    assert llm.max_retries == 5


def test_chat_model_uses_custom_base_and_headers() -> None:
    provider = OpenAICompatibleChatProvider(
        _chat_config(
            base_url="https://example.test/v1",
            default_headers={"X-Test-Header": "test"},
        )
    )

    llm = provider.get_chat_model()

    assert llm.openai_api_base == "https://example.test/v1"
    assert llm.default_headers == {"X-Test-Header": "test"}


def test_embedding_provider_builds_separate_code_and_docs_models() -> None:
    provider = OpenAICompatibleEmbeddingProvider(
        _embedding_config(
            base_url="https://example.test/v1",
            default_headers={"X-Test-Header": "test"},
            code_extra_kwargs={"dimensions": 1536},
        )
    )

    code_embeddings = provider.get_embed_model_code()
    docs_embeddings = provider.get_embed_model_docs()
    code_client = cast(Any, code_embeddings._client)
    docs_client = cast(Any, docs_embeddings._client)

    assert isinstance(code_embeddings, LangChainEmbeddingAdapter)
    assert isinstance(docs_embeddings, LangChainEmbeddingAdapter)
    assert code_embeddings.model_name == "text-embedding-3-large"
    assert docs_embeddings.model_name == "text-embedding-3-small"
    assert code_client.model == "text-embedding-3-large"
    assert docs_client.model == "text-embedding-3-small"
    assert code_client.openai_api_base == "https://example.test/v1"
    assert code_client.default_headers == {"X-Test-Header": "test"}
    assert code_client.dimensions == 1536
    assert code_client.check_embedding_ctx_length is True
    llama_provider = LlamaCppEmbeddingProvider(_embedding_config())
    for embedding in (
        llama_provider.get_embed_model_code(),
        llama_provider.get_embed_model_docs(),
    ):
        assert cast(Any, embedding._client).check_embedding_ctx_length is False


@pytest.mark.parametrize(
    "provider_cls", [OllamaEmbeddingProvider, VLLMEmbeddingProvider]
)
def test_local_embeddings_allow_overriding_raw_text_default(provider_cls) -> None:
    provider = provider_cls(
        _embedding_config(
            base_url="http://localhost:8000/v1",
            code_extra_kwargs={"check_embedding_ctx_length": True},
        )
    )
    assert provider.get_embed_model_code()._client.check_embedding_ctx_length is True
    assert provider.get_embed_model_docs()._client.check_embedding_ctx_length is False


def test_vllm_accepts_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    chat = VLLMProvider(
        _chat_config(api_key=None, base_url="http://localhost:8000/v1")
    ).get_chat_model()
    embedding = VLLMEmbeddingProvider(
        _embedding_config(api_key=None, base_url="http://localhost:8000/v1")
    ).get_embed_model_code()
    assert chat.openai_api_key.get_secret_value() == "sk-no-key-required"
    assert embedding._client.openai_api_key.get_secret_value() == "sk-no-key-required"


def test_single_text_embeddings_use_document_mode() -> None:
    client = Mock(spec=Embeddings)
    client.embed_documents.return_value = [[2.0]]
    client.aembed_documents.return_value = [[2.0]]
    adapter = LangChainEmbeddingAdapter(client, model_name="test-model")

    assert adapter.get_text_embedding("text") == [2.0]
    assert asyncio.run(adapter.aget_text_embedding("text")) == [2.0]
    client.embed_documents.assert_called_once_with(["text"])
    client.aembed_documents.assert_awaited_once_with(["text"])
