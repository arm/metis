# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

import pytest

pytest.importorskip("langchain_anthropic")

from langchain_anthropic import ChatAnthropic
from langchain_core.callbacks.base import BaseCallbackHandler

from metis.providers.anthropic import AnthropicProvider


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


def test_chat_model_allows_runtime_overrides_and_callbacks():
    provider = AnthropicProvider(_config())
    callback = Mock(spec=BaseCallbackHandler)

    llm = provider.get_chat_model(
        model="claude-opus-4-1-20250805",
        callbacks=[callback],
        max_tokens=128,
    )

    assert llm.model == "claude-opus-4-1-20250805"
    assert llm.callbacks == [callback]
    assert llm.max_tokens == 128


def test_chat_model_accepts_top_p():
    provider = AnthropicProvider(_config())

    llm = provider.get_chat_model(top_p=0.8)

    assert llm.top_p == 0.8


def test_provider_requires_api_key():
    with pytest.raises(ValueError) as exc_info:
        AnthropicProvider(_config(api_key=""))

    assert "ANTHROPIC_API_KEY" in str(exc_info.value)
