# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from unittest.mock import Mock

import pytest

pytest.importorskip("langchain_anthropic")

from langchain_anthropic import ChatAnthropic
from anthropic import Anthropic
import httpx2 as httpx
from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.messages import HumanMessage
from langchain_core.messages import SystemMessage

from metis.providers.anthropic import AnthropicProvider
from metis.providers.bedrock_mantle import BedrockMantleProvider


def _config(**overrides):
    config = {
        "api_key": "anthropic-key",
        "model": "claude-opus-4-1-20250805",
    }
    config.update(overrides)
    return config


def test_chat_model_uses_anthropic_configuration():
    provider = AnthropicProvider(_config())

    llm = provider.get_chat_model()

    assert isinstance(llm, ChatAnthropic)
    assert llm.model == "claude-opus-4-1-20250805"


@pytest.mark.parametrize("provider_type", (AnthropicProvider, BedrockMantleProvider))
def test_chat_model_allows_runtime_overrides_and_callbacks(provider_type):
    provider = provider_type(_config())
    callback = Mock(spec=BaseCallbackHandler)

    llm = provider.get_chat_model(
        "positional-model",
        model="runtime-model",
        callbacks=[callback],
        max_tokens="128",
        max_retries=0,
        timeout=7,
        top_k=4,
        top_p=None,
        stop_sequences=["stop"],
    )

    assert llm.model == "runtime-model"
    assert llm.callbacks == [callback]
    assert llm.max_tokens == 128
    assert llm.max_retries == 0
    assert llm.default_request_timeout == 7
    assert llm.top_k == 4
    assert llm.top_p is None
    assert llm.stop_sequences == ["stop"]
    assert provider.get_chat_model("positional-model").model == "positional-model"
    assert provider.get_chat_model(model="").model == provider.default_model


@pytest.mark.parametrize("provider_type", (AnthropicProvider, BedrockMantleProvider))
@pytest.mark.parametrize("supports_temperature", (False, True))
def test_claude_sampling_conflict_preserves_provider_policy(
    provider_type, supports_temperature
):
    provider = provider_type(_config(supports_temperature=supports_temperature))
    for temperature in (None, 0.5):
        if supports_temperature or provider_type is AnthropicProvider:
            with pytest.raises(ValueError, match="either temperature or top_p"):
                provider.get_chat_model(temperature=temperature, top_p=0.8)
        else:
            llm = provider.get_chat_model(temperature=temperature, top_p=0.8)
            assert llm.temperature is None
            assert llm.top_p == 0.8


def test_chat_model_accepts_top_p():
    provider = AnthropicProvider(_config())

    llm = provider.get_chat_model(top_p=0.8)

    assert llm.top_p == 0.8


@pytest.mark.parametrize("supports_temperature", [False, True])
@pytest.mark.parametrize("provider_type", (AnthropicProvider, BedrockMantleProvider))
@pytest.mark.parametrize(
    "options", [{}, {"temperature": None}, {"temperature": 0.0}, {"temperature": 0.7}]
)
def test_chat_model_forwards_optional_temperature(
    monkeypatch, supports_temperature, options, provider_type
):
    provider = provider_type(_config(supports_temperature=supports_temperature))
    llm = provider.get_chat_model(**options)
    requests = []

    def respond(request):
        requests.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "msg_test",
                "type": "message",
                "role": "assistant",
                "model": llm.model,
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )

    with Anthropic(
        api_key="test-key",
        http_client=httpx.Client(transport=httpx.MockTransport(respond)),
    ) as client:
        monkeypatch.setattr(type(llm), "_client", property(lambda self: client))
        response = llm.invoke(
            [SystemMessage(content="Review code."), HumanMessage(content="int value;")]
        )

    assert response.content == "ok"
    assert len(requests) == 1
    payload = requests[0]

    assert payload["system"] == "Review code."
    if not supports_temperature or options.get("temperature") is None:
        assert "temperature" not in payload
    else:
        assert payload["temperature"] == options["temperature"]


def test_provider_requires_api_key():
    with pytest.raises(ValueError) as exc_info:
        AnthropicProvider(_config(api_key=""))

    assert "ANTHROPIC_API_KEY" in str(exc_info.value)
