# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import cast

from langchain_openai import ChatOpenAI
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.llms.openai import OpenAIResponses
from metis.providers.base import OpenAICompatibleProviderConfig

from metis.providers.llamacpp import LlamaCppProvider


def _config(**overrides: object) -> OpenAICompatibleProviderConfig:
    config: dict[str, object] = {
        "llm_api_key": "test-key",
        "model": "llama3.1:8b",
        "llama_query_model": "llama3.1:8b",
        "llama_query_temperature": 0.0,
        "llama_query_max_tokens": 256,
        "code_embedding_model": "nomic-embed-text:v1.5",
        "docs_embedding_model": "nomic-embed-text:v1.5",
    }
    config.update(overrides)
    return cast(OpenAICompatibleProviderConfig, config)


def test_defaults_base_url_when_not_configured() -> None:
    config = _config()
    config.pop("llm_api_key", None)
    provider = LlamaCppProvider(config)

    assert provider.base_url == "http://localhost:8080/v1"


def test_uses_configured_base_url() -> None:
    provider = LlamaCppProvider(_config(openai_api_base="http://custom:9000/v1"))

    assert provider.base_url == "http://custom:9000/v1"


def test_uses_placeholder_api_key_when_none_provided() -> None:
    config = _config()
    config.pop("llm_api_key", None)
    provider = LlamaCppProvider(config)

    assert provider.api_key == "sk-no-key-required"


def test_uses_configured_api_key() -> None:
    provider = LlamaCppProvider(_config(llm_api_key="my-secret-key"))

    assert provider.api_key == "my-secret-key"


def test_raises_on_missing_query_model() -> None:
    config = _config()
    config["model"] = ""
    config["llama_query_model"] = ""
    config.pop("llm_api_key", None)

    try:
        LlamaCppProvider(config)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "query model" in str(exc)


def test_raises_on_missing_embedding_models() -> None:
    config = _config()
    config["code_embedding_model"] = ""
    config.pop("llm_api_key", None)

    try:
        LlamaCppProvider(config)
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert "embedding model" in str(exc)


def test_chat_model_uses_configured_base_url() -> None:
    provider = LlamaCppProvider(
        _config(openai_api_base="http://custom:9000/v1", llm_api_key="test-key")
    )

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatOpenAI)
    assert llm.openai_api_base == "http://custom:9000/v1"


def test_query_engine_uses_responses_llm() -> None:
    provider = LlamaCppProvider(_config(llm_api_key="test-key"))

    llm_class = provider.get_query_engine_class()
    assert llm_class is OpenAIResponses


def test_query_model_kwargs_include_base_url() -> None:
    provider = LlamaCppProvider(
        _config(
            openai_api_base="http://custom:9000/v1",
            llama_query_model="llama3.1:8b",
            llm_api_key="test-key",
        )
    )

    params = provider.get_query_model_kwargs()

    assert params["api_base"] == "http://custom:9000/v1"
    assert params["model"] == "llama3.1:8b"


def test_context_window_set_for_custom_base_url() -> None:
    provider = LlamaCppProvider(
        _config(
            openai_api_base="http://custom:9000/v1",
            llama_query_context_window=32768,
            llm_api_key="test-key",
        )
    )

    params = provider.get_query_model_kwargs()

    assert params["context_window"] == 32768


def test_reasoning_effort_propagated_to_chat_model() -> None:
    provider = LlamaCppProvider(
        _config(
            llama_query_reasoning_effort="high",
            llm_api_key="test-key",
        )
    )

    llm = provider.get_chat_model()

    assert llm.reasoning_effort == "high"


def test_reasoning_effort_propagated_to_query_kwargs() -> None:
    provider = LlamaCppProvider(
        _config(
            llama_query_reasoning_effort="low",
            llm_api_key="test-key",
        )
    )

    params = provider.get_query_model_kwargs()

    assert params["reasoning_options"] == {"effort": "low"}
    additional_kwargs = params["additional_kwargs"]
    assert additional_kwargs["reasoning"] == {"effort": "low"}


def test_embed_model_code_returns_openai_embedding() -> None:
    provider = LlamaCppProvider(_config(llm_api_key="test-key"))

    embed = provider.get_embed_model_code()

    assert isinstance(embed, OpenAIEmbedding)
    assert embed.model_name == "nomic-embed-text:v1.5"


def test_embed_model_docs_returns_openai_embedding() -> None:
    provider = LlamaCppProvider(_config(llm_api_key="test-key"))

    embed = provider.get_embed_model_docs()

    assert isinstance(embed, OpenAIEmbedding)
    assert embed.model_name == "nomic-embed-text:v1.5"


def test_lazy_loader_is_registered() -> None:
    from metis.providers.registry import _LOADERS, get_provider

    # Lazy loader entry must exist
    assert _LOADERS.get("llamacpp") == "metis.providers.llamacpp:LlamaCppProvider"

    # get_provider must return the class (lazy loader triggers on first call)
    cls = get_provider("llamacpp")
    assert cls.__name__ == "LlamaCppProvider"
    assert cls.__module__ == "metis.providers.llamacpp"


def test_ollama_lazy_loader_is_registered() -> None:
    from metis.providers.registry import _LOADERS, get_provider

    assert _LOADERS.get("ollama") == "metis.providers.ollama:OllamaProvider"
    cls = get_provider("ollama")
    assert cls.__name__ == "OllamaProvider"
    assert cls.__module__ == "metis.providers.ollama"
