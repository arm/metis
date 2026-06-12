# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import cast

import pytest
from langchain_openai import ChatOpenAI

from metis.providers.llamacpp import LlamaCppEmbeddingProvider
from metis.providers.llamacpp import LlamaCppProvider
from metis.providers.openai_compatible import OpenAICompatibleChatConfig
from metis.providers.openai_compatible import OpenAICompatibleEmbeddingConfig


def _chat_config(**overrides: object) -> OpenAICompatibleChatConfig:
    config: dict[str, object] = {
        "api_key": "test-key",
        "model": "llama3.1:8b",
    }
    config.update(overrides)
    return cast(OpenAICompatibleChatConfig, config)


def _embedding_config(**overrides: object) -> OpenAICompatibleEmbeddingConfig:
    config: dict[str, object] = {
        "api_key": "test-key",
        "code_embedding_model": "nomic-embed-text:v1.5",
        "docs_embedding_model": "nomic-embed-text:v1.5",
    }
    config.update(overrides)
    return cast(OpenAICompatibleEmbeddingConfig, config)


def test_defaults_base_url_when_not_configured() -> None:
    config = _chat_config()
    config.pop("api_key", None)
    provider = LlamaCppProvider(config)

    assert provider.base_url == "http://localhost:8080/v1"


def test_uses_configured_base_url() -> None:
    provider = LlamaCppProvider(_chat_config(base_url="http://custom:9000/v1"))

    assert provider.base_url == "http://custom:9000/v1"


def test_uses_placeholder_api_key_when_none_provided() -> None:
    config = _chat_config()
    config.pop("api_key", None)
    provider = LlamaCppProvider(config)

    assert provider.api_key == "sk-no-key-required"


def test_uses_configured_api_key() -> None:
    provider = LlamaCppProvider(_chat_config(api_key="my-secret-key"))

    assert provider.api_key == "my-secret-key"


def test_raises_on_missing_query_model() -> None:
    config = _chat_config(model="")
    config.pop("api_key", None)

    with pytest.raises(ValueError) as exc_info:
        LlamaCppProvider(config)

    assert "chat model" in str(exc_info.value)


def test_raises_on_missing_embedding_models() -> None:
    config = _embedding_config(code_embedding_model="")
    config.pop("api_key", None)

    with pytest.raises(ValueError) as exc_info:
        LlamaCppEmbeddingProvider(config)

    assert "embedding model" in str(exc_info.value)


def test_chat_model_uses_configured_base_url() -> None:
    provider = LlamaCppProvider(
        _chat_config(base_url="http://custom:9000/v1", api_key="test-key")
    )

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatOpenAI)
    assert llm.openai_api_base == "http://custom:9000/v1"
