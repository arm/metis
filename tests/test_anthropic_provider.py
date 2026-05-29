# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

import pytest
from langchain_anthropic import ChatAnthropic
from langchain_core.callbacks.base import BaseCallbackHandler
from llama_index.core.callbacks import CallbackManager
from llama_index.llms.langchain import LangChainLLM

from metis.providers.anthropic import AnthropicProvider


def _config(**overrides):
    config = {
        "llm_api_key": "anthropic-key",
        "embedding_api_key": "embedding-key",
        "model": "claude-opus-4-1-20250805",
        "llama_query_model": "claude-opus-4-1-20250805",
        "llama_query_temperature": 0.2,
        "llama_query_max_tokens": 256,
        "code_embedding_model": "text-embedding-3-large",
        "docs_embedding_model": "text-embedding-3-small",
    }
    config.update(overrides)
    return config


def test_chat_model_uses_anthropic_configuration():
    provider = AnthropicProvider(_config())

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatAnthropic)
    assert llm.model == "claude-opus-4-1-20250805"
    assert llm.max_tokens == 256
    assert llm.temperature == 0.2


def test_chat_model_allows_runtime_overrides_and_callbacks():
    provider = AnthropicProvider(_config())
    callback = Mock(spec=BaseCallbackHandler)

    llm = provider.get_chat_model(
        model="claude-opus-4-1-20250805",
        callbacks=[callback],
        max_tokens=128,
        temperature=0.0,
    )

    assert llm.model == "claude-opus-4-1-20250805"
    assert llm.callbacks == [callback]
    assert llm.max_tokens == 128
    assert llm.temperature == 0.0


def test_chat_model_top_p_omits_default_temperature():
    provider = AnthropicProvider(_config())

    llm = provider.get_chat_model(top_p=0.8)

    assert llm.top_p == 0.8
    assert llm.temperature is None


def test_chat_model_rejects_temperature_and_top_p_together():
    provider = AnthropicProvider(_config())

    with pytest.raises(ValueError) as exc_info:
        provider.get_chat_model(temperature=0.0, top_p=0.8)

    assert "either temperature or top_p" in str(exc_info.value)


def test_query_engine_uses_langchain_adapter():
    provider = AnthropicProvider(_config())

    assert provider.get_query_engine_class() is LangChainLLM

    llm = provider.get_query_model_kwargs()["llm"]
    assert isinstance(llm, ChatAnthropic)
    assert llm.model == "claude-opus-4-1-20250805"


def test_provider_accepts_callback_manager_for_query_and_embeddings():
    provider = AnthropicProvider(_config())
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


def test_embedding_models_use_openai_compatible_embeddings():
    provider = AnthropicProvider(_config())

    code_embeddings = provider.get_embed_model_code()
    docs_embeddings = provider.get_embed_model_docs()

    assert code_embeddings.model_name == "text-embedding-3-large"
    assert docs_embeddings.model_name == "text-embedding-3-small"


def test_custom_openai_compatible_embedding_model_name_is_preserved():
    provider = AnthropicProvider(
        _config(
            code_embedding_model="custom-embedding",
            docs_embedding_model="custom-embedding",
        )
    )

    embeddings = provider.get_embed_model_code()

    assert embeddings.model_name == "custom-embedding"
