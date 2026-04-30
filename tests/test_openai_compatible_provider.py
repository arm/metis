# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from langchain_openai import ChatOpenAI

from metis.providers.openai_compatible import OpenAICompatibleProvider


def _config(**overrides):
    config = {
        "llm_api_key": "test-key",
        "model": "gpt-test",
        "llama_query_model": "gpt-test",
        "llama_query_temperature": 0.0,
        "llama_query_max_tokens": 256,
        "code_embedding_model": "text-embedding-3-large",
        "docs_embedding_model": "text-embedding-3-large",
    }
    config.update(overrides)
    return config


def test_chat_model_uses_configured_reasoning_effort():
    provider = OpenAICompatibleProvider(_config(llama_query_reasoning_effort="high"))

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatOpenAI)
    assert llm.reasoning_effort == "high"


def test_query_model_kwargs_include_configured_reasoning_effort():
    provider = OpenAICompatibleProvider(_config(llama_query_reasoning_effort="low"))

    params = provider.get_query_model_kwargs()

    assert params["reasoning_effort"] == "low"


def test_reasoning_effort_is_omitted_when_unconfigured():
    provider = OpenAICompatibleProvider(_config())

    params = provider.get_query_model_kwargs()

    assert "reasoning_effort" not in params
