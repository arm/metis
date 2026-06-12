# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Any, cast
from unittest.mock import Mock

from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_openai import AzureChatOpenAI
from llama_index.core.callbacks import CallbackManager

from metis.providers.azure_openai import AzureOpenAIChatConfig
from metis.providers.azure_openai import AzureOpenAIEmbeddingConfig
from metis.providers.azure_openai import AzureOpenAIEmbeddingProvider
from metis.providers.azure_openai import AzureOpenAIProvider


def _chat_config(**overrides: object) -> AzureOpenAIChatConfig:
    config: dict[str, object] = {
        "api_key": "test-key",
        "azure_endpoint": "https://example.openai.azure.com/",
        "azure_api_version": "2024-02-01",
        "engine": "chat-deployment",
        "chat_deployment_model": "gpt-4o-mini",
    }
    config.update(overrides)
    return cast(AzureOpenAIChatConfig, config)


def _embedding_config(**overrides: object) -> AzureOpenAIEmbeddingConfig:
    config: dict[str, object] = {
        "api_key": "test-key",
        "azure_endpoint": "https://example.openai.azure.com/",
        "azure_api_version": "2024-02-01",
        "code_embedding_model": "text-embedding-3-large",
        "docs_embedding_model": "text-embedding-3-small",
        "code_deployment": "code-embedding-deployment",
        "docs_deployment": "docs-embedding-deployment",
    }
    config.update(overrides)
    return cast(AzureOpenAIEmbeddingConfig, config)


def test_chat_model_uses_configured_deployment() -> None:
    provider = AzureOpenAIProvider(_chat_config())

    llm = provider.get_chat_model(response_format=None)

    assert isinstance(llm, AzureChatOpenAI)
    assert llm.deployment_name == "chat-deployment"
    assert llm.model_name == "gpt-4o-mini"
    assert llm.use_responses_api is not True
    assert llm.max_tokens is None


def test_chat_model_can_use_responses_api() -> None:
    provider = AzureOpenAIProvider(_chat_config(use_responses_api=True))

    llm = provider.get_chat_model(response_format=None)

    assert llm.use_responses_api is True


def test_embedding_adapter_preserves_azure_config() -> None:
    provider = AzureOpenAIEmbeddingProvider(_embedding_config())

    code_embeddings = provider.get_embed_model_code()
    docs_embeddings = provider.get_embed_model_docs()
    code_client = cast(Any, code_embeddings._client)
    docs_client = cast(Any, docs_embeddings._client)

    assert code_embeddings.model_name == "text-embedding-3-large"
    assert docs_embeddings.model_name == "text-embedding-3-small"
    assert code_client.model == "text-embedding-3-large"
    assert docs_client.model == "text-embedding-3-small"
    assert code_client.deployment == "code-embedding-deployment"
    assert docs_client.deployment == "docs-embedding-deployment"


def test_providers_accept_separate_chat_and_embedding_callbacks() -> None:
    chat_provider = AzureOpenAIProvider(_chat_config())
    embedding_provider = AzureOpenAIEmbeddingProvider(_embedding_config())
    callback_manager = CallbackManager([])
    callback = cast(BaseCallbackHandler, Mock(spec=BaseCallbackHandler))

    chat = chat_provider.get_chat_model(callbacks=[callback], response_format=None)
    embeddings = embedding_provider.get_embed_model_code(
        callback_manager=callback_manager
    )

    assert isinstance(chat, AzureChatOpenAI)
    assert chat.callbacks == [callback]
    assert embeddings.callback_manager is callback_manager


def test_provider_passes_reasoning_effort_to_chat_model() -> None:
    provider = AzureOpenAIProvider(_chat_config())

    llm = provider.get_chat_model(response_format=None, reasoning_effort="medium")

    assert llm.reasoning_effort == "medium"
    assert llm.use_responses_api is not True
