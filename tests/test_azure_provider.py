# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import cast

from langchain_openai import AzureChatOpenAI
from llama_index.core.callbacks import CallbackManager
from langchain_core.callbacks.base import BaseCallbackHandler
from unittest.mock import Mock

from metis.providers.azure_openai import AzureOpenAIProvider
from metis.providers.base import AzureOpenAIProviderConfig


def _config() -> AzureOpenAIProviderConfig:
    return {
        "llm_api_key": "test-key",
        "azure_endpoint": "https://example.openai.azure.com/",
        "azure_api_version": "2024-02-01",
        "engine": "chat-deployment",
        "chat_deployment_model": "gpt-4o-mini",
        "code_embedding_model": "text-embedding-3-large",
        "docs_embedding_model": "text-embedding-3-small",
    }


def test_chat_model_uses_configured_deployment() -> None:
    provider = AzureOpenAIProvider(_config())

    llm = provider.get_chat_model(response_format=None)

    assert isinstance(llm, AzureChatOpenAI)
    assert llm.deployment_name == "chat-deployment"
    assert llm.model_name == "gpt-4o-mini"
    assert llm.use_responses_api is True
    assert llm.max_tokens == 3072


def test_embedding_adapter_preserves_azure_config() -> None:
    provider = AzureOpenAIProvider(_config())

    code_embeddings = provider.get_embed_model_code()
    docs_embeddings = provider.get_embed_model_docs()

    assert code_embeddings.model_name == "text-embedding-3-large"
    assert docs_embeddings.model_name == "text-embedding-3-small"
    assert code_embeddings._client.model == "text-embedding-3-large"
    assert docs_embeddings._client.model == "text-embedding-3-small"


def test_provider_accepts_callbacks_and_embedding_callback_manager() -> None:
    provider = AzureOpenAIProvider(_config())
    callback_manager = CallbackManager([])
    callback = cast(BaseCallbackHandler, Mock(spec=BaseCallbackHandler))

    chat = provider.get_chat_model(callbacks=[callback], response_format=None)
    embeddings = provider.get_embed_model_code(callback_manager=callback_manager)

    assert isinstance(chat, AzureChatOpenAI)
    assert chat.callbacks == [callback]
    assert embeddings.callback_manager is callback_manager


def test_provider_does_not_apply_chat_callbacks_to_embeddings() -> None:
    provider = AzureOpenAIProvider(_config())
    callback = cast(BaseCallbackHandler, Mock(spec=BaseCallbackHandler))

    chat = provider.get_chat_model(callbacks=[callback], response_format=None)
    code_embeddings = provider.get_embed_model_code()

    assert isinstance(chat, AzureChatOpenAI)
    assert chat.callbacks == [callback]
    assert code_embeddings.callback_manager is not chat.callbacks


def test_provider_passes_reasoning_effort_to_chat_model() -> None:
    config = _config()
    config["llama_query_reasoning_effort"] = "medium"
    provider = AzureOpenAIProvider(config)

    llm = provider.get_chat_model(response_format=None)

    assert llm.reasoning_effort == "medium"
    assert llm.use_responses_api is True
