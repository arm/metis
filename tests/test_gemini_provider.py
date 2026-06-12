# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

import pytest

pytest.importorskip("langchain_google_genai")

from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_google_genai import ChatGoogleGenerativeAI

from metis.providers.gemini import GeminiProvider


def _config(**overrides):
    config = {
        "api_key": "google-key",
        "model": "gemini-2.5-flash",
    }
    config.update(overrides)
    return config


def test_chat_model_uses_gemini_configuration():
    provider = GeminiProvider(_config())

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatGoogleGenerativeAI)
    assert llm.model == "gemini-2.5-flash"
    assert llm.max_output_tokens is None
    assert llm.google_api_key.get_secret_value() == "google-key"


def test_chat_model_allows_runtime_overrides_and_callbacks():
    provider = GeminiProvider(_config())
    callback = Mock(spec=BaseCallbackHandler)

    llm = provider.get_chat_model(
        model="gemini-2.5-pro",
        callbacks=[callback],
        max_tokens=128,
        top_p=0.8,
        top_k=32,
    )

    assert llm.model == "gemini-2.5-pro"
    assert llm.callbacks == [callback]
    assert llm.max_output_tokens == 128
    assert llm.top_p == 0.8
    assert llm.top_k == 32


def test_chat_model_maps_openai_json_response_format():
    provider = GeminiProvider(_config())

    llm = provider.get_chat_model(response_format={"type": "json_object"})

    assert llm.response_mime_type == "application/json"


def test_chat_model_maps_supported_reasoning_effort_to_thinking_level():
    provider = GeminiProvider(_config())

    llm = provider.get_chat_model(reasoning_effort="high")

    assert llm.thinking_level == "high"


def test_common_backend_params_are_forwarded_to_chat():
    provider = GeminiProvider(
        _config(
            base_url="https://example.test/gemini",
            additional_headers={"X-Test-Header": "test"},
            project="test-project",
            location="europe-west2",
            vertexai=False,
            client_args={"timeout": 30},
        )
    )

    llm = provider.get_chat_model()

    assert llm.base_url == "https://example.test/gemini"
    assert llm.additional_headers == {"X-Test-Header": "test"}
    assert llm.project == "test-project"
    assert llm.location == "europe-west2"
    assert llm.vertexai is False
    assert llm.client_args == {"timeout": 30}


def test_provider_requires_api_key():
    with pytest.raises(ValueError) as exc_info:
        GeminiProvider(_config(api_key=""))

    assert "GOOGLE_API_KEY or GEMINI_API_KEY" in str(exc_info.value)


def test_provider_allows_vertex_ai_without_api_key():
    provider = GeminiProvider(
        _config(
            api_key="",
            project="test-project",
            location="europe-west2",
            vertexai=True,
        )
    )

    assert provider.api_key == ""
    assert provider.vertexai is True


def test_provider_requires_chat_model():
    with pytest.raises(ValueError) as exc_info:
        GeminiProvider(_config(model=""))

    assert "chat model" in str(exc_info.value)
