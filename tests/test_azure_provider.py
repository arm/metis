# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from langchain_openai import AzureChatOpenAI
from llama_index.core.callbacks import CallbackManager
from llama_index.llms.langchain import LangChainLLM
from langchain_core.callbacks.base import BaseCallbackHandler
from unittest.mock import Mock

from metis.providers.azure_openai import AzureOpenAIProvider


def _config():
    return {
        "llm_api_key": "test-key",
        "azure_endpoint": "https://example.openai.azure.com/",
        "azure_api_version": "2024-02-01",
        "engine": "chat-deployment",
        "chat_deployment_model": "gpt-4o-mini",
        "code_embedding_model": "text-embedding-3-large",
        "docs_embedding_model": "text-embedding-3-small",
    }


def test_query_engine_uses_langchain_adapter():
    provider = AzureOpenAIProvider(_config())

    assert provider.get_query_engine_class() is LangChainLLM

    llm = provider.get_query_model_kwargs()["llm"]
    assert isinstance(llm, AzureChatOpenAI)
    assert llm.deployment_name == "chat-deployment"
    assert llm.model_name == "gpt-4o-mini"


def test_embedding_adapter_preserves_azure_config():
    provider = AzureOpenAIProvider(_config())

    code_embeddings = provider.get_embed_model_code()
    docs_embeddings = provider.get_embed_model_docs()

    assert code_embeddings.model_name == "text-embedding-3-large"
    assert docs_embeddings.model_name == "text-embedding-3-small"
    assert code_embeddings._client.model == "text-embedding-3-large"
    assert docs_embeddings._client.model == "text-embedding-3-small"


def test_provider_accepts_callback_manager_for_query_and_embeddings():
    provider = AzureOpenAIProvider(_config())
    callback_manager = CallbackManager([])
    callback = Mock(spec=BaseCallbackHandler)

    query_kwargs = provider.get_query_model_kwargs(
        callback_manager=callback_manager,
        callbacks=[callback],
    )
    embeddings = provider.get_embed_model_code(callback_manager=callback_manager)

    assert query_kwargs["callback_manager"] is callback_manager
    assert query_kwargs["llm"].callbacks == [callback]
    assert embeddings.callback_manager is callback_manager


def test_provider_uses_explicit_callbacks_without_mutation():
    provider = AzureOpenAIProvider(_config())
    callback_manager = Mock(name="callback_manager")
    callback = Mock(spec=BaseCallbackHandler)

    query_kwargs = provider.get_query_model_kwargs(
        callback_manager=callback_manager,
        callbacks=[callback],
    )
    code_embeddings = provider.get_embed_model_code()

    assert query_kwargs["llm"].callbacks == [callback]
    assert query_kwargs["callback_manager"] is callback_manager
    assert code_embeddings.callback_manager is not callback_manager
