# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from langchain_openai import ChatOpenAI
from llama_index.llms.openai import OpenAIResponses

from metis.providers.openai_compatible import OpenAICompatibleProvider


def _config(**overrides: Any) -> dict[str, Any]:
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


def test_chat_model_uses_configured_reasoning_effort() -> None:
    provider = OpenAICompatibleProvider(_config(llama_query_reasoning_effort="high"))

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatOpenAI)
    assert llm.reasoning_effort == "high"
    assert llm.use_responses_api is True


def test_query_engine_uses_responses_llm() -> None:
    provider = OpenAICompatibleProvider(_config())

    assert provider.get_query_engine_class() is OpenAIResponses
    params = provider.get_query_model_kwargs()
    llm = provider.get_query_engine_class()(**params)

    assert isinstance(llm, OpenAIResponses)
    assert params["max_output_tokens"] == 256
    assert "max_tokens" not in params


def test_query_model_kwargs_include_configured_reasoning_effort() -> None:
    provider = OpenAICompatibleProvider(_config(llama_query_reasoning_effort="low"))

    params = provider.get_query_model_kwargs()

    assert params["reasoning_options"] == {"effort": "low"}
    assert params["additional_kwargs"]["reasoning"] == {"effort": "low"}


def test_reasoning_effort_is_omitted_when_unconfigured() -> None:
    provider = OpenAICompatibleProvider(_config())

    params = provider.get_query_model_kwargs()

    assert "reasoning_options" not in params
    assert "additional_kwargs" not in params


def test_custom_base_sets_context_window_for_responses_llm() -> None:
    provider = OpenAICompatibleProvider(
        _config(
            openai_api_base="https://example.test/v1",
            llama_query_context_window=32768,
        )
    )

    params = provider.get_query_model_kwargs()

    assert params["api_base"] == "https://example.test/v1"
    assert params["context_window"] == 32768
