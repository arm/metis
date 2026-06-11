# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

import pytest
from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from llama_index.core.callbacks import CallbackManager

from metis.providers.embedding_adapter import LangChainEmbeddingAdapter
from metis.providers.gemini import GeminiProvider


def _config(**overrides):
    config = {
        "llm_api_key": "google-key",
        "model": "gemini-2.5-flash",
        "llama_query_model": "gemini-2.5-flash",
        "llama_query_temperature": 0.2,
        "llama_query_max_tokens": 256,
        "code_embedding_model": "gemini-embedding-001",
        "docs_embedding_model": "gemini-embedding-001",
    }
    config.update(overrides)
    return config


def test_chat_model_uses_gemini_configuration():
    provider = GeminiProvider(_config())

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatGoogleGenerativeAI)
    assert llm.model == "gemini-2.5-flash"
    assert llm.max_output_tokens == 256
    assert llm.temperature == 0.2
    assert llm.google_api_key.get_secret_value() == "google-key"


def test_chat_model_allows_runtime_overrides_and_callbacks():
    provider = GeminiProvider(_config())
    callback = Mock(spec=BaseCallbackHandler)

    llm = provider.get_chat_model(
        model="gemini-2.5-pro",
        callbacks=[callback],
        max_tokens=128,
        temperature=0.0,
        top_p=0.8,
        top_k=32,
    )

    assert llm.model == "gemini-2.5-pro"
    assert llm.callbacks == [callback]
    assert llm.max_output_tokens == 128
    assert llm.temperature == 0.0
    assert llm.top_p == 0.8
    assert llm.top_k == 32


def test_chat_model_maps_openai_json_response_format():
    provider = GeminiProvider(_config())

    llm = provider.get_chat_model(response_format={"type": "json_object"})

    assert llm.response_mime_type == "application/json"


def test_chat_model_maps_supported_reasoning_effort_to_thinking_level():
    provider = GeminiProvider(_config(llama_query_reasoning_effort="high"))

    llm = provider.get_chat_model()

    assert llm.thinking_level == "high"


def test_common_backend_params_are_forwarded_to_chat_and_embeddings():
    provider = GeminiProvider(
        _config(
            gemini_api_base="https://example.test/gemini",
            gemini_additional_headers={"X-Test-Header": "test"},
            gemini_project="test-project",
            gemini_location="europe-west2",
            gemini_vertexai=False,
            gemini_client_args={"timeout": 30},
        )
    )

    llm = provider.get_chat_model()
    embeddings = provider.get_embed_model_code()

    assert llm.base_url == "https://example.test/gemini"
    assert llm.additional_headers == {"X-Test-Header": "test"}
    assert llm.project == "test-project"
    assert llm.location == "europe-west2"
    assert llm.vertexai is False
    assert llm.client_args == {"timeout": 30}
    assert embeddings._client.base_url == "https://example.test/gemini"
    assert embeddings._client.additional_headers == {"X-Test-Header": "test"}
    assert embeddings._client.project == "test-project"
    assert embeddings._client.location == "europe-west2"
    assert embeddings._client.vertexai is False
    assert embeddings._client.client_args == {"timeout": 30}


def test_provider_accepts_callback_manager_for_embeddings():
    provider = GeminiProvider(_config())
    callback_manager = CallbackManager([])

    embeddings = provider.get_embed_model_code(callback_manager=callback_manager)

    assert embeddings.callback_manager is callback_manager


def test_embedding_models_use_native_gemini_embeddings():
    provider = GeminiProvider(
        _config(
            code_embedding_extra_kwargs={"output_dimensionality": 1536},
            docs_embedding_extra_kwargs={"task_type": "RETRIEVAL_DOCUMENT"},
        )
    )

    code_embeddings = provider.get_embed_model_code()
    docs_embeddings = provider.get_embed_model_docs()

    assert isinstance(code_embeddings, LangChainEmbeddingAdapter)
    assert isinstance(docs_embeddings, LangChainEmbeddingAdapter)
    assert isinstance(code_embeddings._client, GoogleGenerativeAIEmbeddings)
    assert isinstance(docs_embeddings._client, GoogleGenerativeAIEmbeddings)
    assert code_embeddings.model_name == "gemini-embedding-001"
    assert docs_embeddings.model_name == "gemini-embedding-001"
    assert code_embeddings._client.model == "gemini-embedding-001"
    assert docs_embeddings._client.model == "gemini-embedding-001"
    assert code_embeddings._client.output_dimensionality == 1536
    assert docs_embeddings._client.task_type == "RETRIEVAL_DOCUMENT"


def test_provider_requires_api_key():
    with pytest.raises(ValueError) as exc_info:
        GeminiProvider(_config(llm_api_key=""))

    assert "GOOGLE_API_KEY or GEMINI_API_KEY" in str(exc_info.value)


def test_provider_allows_vertexai_without_api_key():
    provider = GeminiProvider(
        _config(
            llm_api_key="",
            gemini_vertexai=True,
            gemini_project="test-project",
            gemini_location="europe-west2",
        )
    )

    llm = provider.get_chat_model()

    assert llm.vertexai is True
    assert llm.google_api_key is None


def test_embedding_model_required_only_when_used():
    provider = GeminiProvider(_config(code_embedding_model=""))

    llm = provider.get_chat_model()
    assert llm.model == "gemini-2.5-flash"

    with pytest.raises(ValueError) as exc_info:
        provider.get_embed_model_code()

    assert "code_embedding_model" in str(exc_info.value)
