# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import cast

from langchain_openai import ChatOpenAI
from metis.providers.base import OpenAICompatibleProviderConfig

from metis.providers.openai_compatible import OpenAICompatibleProvider


def _config(**overrides: object) -> OpenAICompatibleProviderConfig:
    config: dict[str, object] = {
        "llm_api_key": "test-key",
        "model": "gpt-test",
        "llama_query_model": "gpt-test",
        "llama_query_temperature": 0.0,
        "llama_query_max_tokens": 256,
        "code_embedding_model": "text-embedding-3-large",
        "docs_embedding_model": "text-embedding-3-large",
    }
    config.update(overrides)
    return cast(OpenAICompatibleProviderConfig, config)


def test_chat_model_uses_configured_reasoning_effort() -> None:
    provider = OpenAICompatibleProvider(_config(llama_query_reasoning_effort="high"))

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatOpenAI)
    assert llm.reasoning_effort == "high"
    assert llm.use_responses_api is True


def test_chat_model_uses_configured_max_tokens() -> None:
    provider = OpenAICompatibleProvider(_config())

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatOpenAI)
    assert llm.max_tokens == 256


def test_chat_model_uses_default_max_tokens() -> None:
    config = dict(_config())
    config.pop("llama_query_max_tokens")
    provider = OpenAICompatibleProvider(cast(OpenAICompatibleProviderConfig, config))

    llm = provider.get_chat_model()

    assert llm.max_tokens == 3072


def test_reasoning_effort_is_omitted_when_unconfigured() -> None:
    provider = OpenAICompatibleProvider(_config())

    llm = provider.get_chat_model()

    assert getattr(llm, "reasoning_effort", None) is None


def test_chat_model_uses_custom_base_and_headers() -> None:
    provider = OpenAICompatibleProvider(
        _config(
            openai_api_base="https://example.test/v1",
            openai_default_headers={"X-Test-Header": "test"},
        )
    )

    llm = provider.get_chat_model()

    assert llm.openai_api_base == "https://example.test/v1"
    assert llm.default_headers == {"X-Test-Header": "test"}
