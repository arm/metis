# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

from metis.providers.base import ChatProvider
from metis.utils import (
    anthropic_token_count,
    heuristic_token_count,
    tiktoken_token_count,
)


TEXT = "def add(a, b):\n    return a + b\n"


class _StubProvider(ChatProvider):
    def get_chat_model(self, *args, callbacks=None, **kwargs):
        raise NotImplementedError


def test_base_provider_uses_chars_per_token_heuristic():
    assert _StubProvider({}).count_tokens(TEXT) == heuristic_token_count(TEXT)
    assert _StubProvider({}).count_tokens("") == 0


def test_openai_compatible_provider_uses_tiktoken():
    from metis.providers.openai_compatible import OpenAICompatibleChatProvider

    provider = OpenAICompatibleChatProvider({"api_key": "k", "model": "gpt-4o"})
    assert provider.count_tokens(TEXT) == tiktoken_token_count(TEXT, "gpt-4o")


def test_azure_openai_provider_uses_tiktoken():
    from metis.providers.azure_openai import AzureOpenAIProvider

    provider = AzureOpenAIProvider(
        {
            "api_key": "k",
            "azure_endpoint": "https://example",
            "azure_api_version": "2024-01-01",
            "engine": "deploy",
            "chat_deployment_model": "gpt-4o",
        }
    )
    assert provider.count_tokens(TEXT) == tiktoken_token_count(TEXT, "gpt-4o")


def test_anthropic_provider_uses_anthropic_heuristic():
    pytest.importorskip("langchain_anthropic")
    from metis.providers.anthropic import AnthropicProvider

    provider = AnthropicProvider({"api_key": "k", "model": "claude-sonnet-4-6"})
    assert provider.count_tokens(TEXT) == anthropic_token_count(TEXT)


def test_bedrock_mantle_provider_uses_anthropic_heuristic():
    pytest.importorskip("langchain_anthropic")
    from metis.providers.bedrock_mantle import BedrockMantleProvider

    provider = BedrockMantleProvider({"model": "claude-sonnet-4-6"})
    assert provider.count_tokens(TEXT) == anthropic_token_count(TEXT)


def test_bedrock_provider_dispatches_on_model_id():
    pytest.importorskip("langchain_aws")
    from metis.providers.bedrock import BedrockProvider

    claude = BedrockProvider(
        {"region": "us-east-1", "model": "us.anthropic.claude-3-5-sonnet-v2:0"}
    )
    assert claude.count_tokens(TEXT) == anthropic_token_count(TEXT)

    titan = BedrockProvider(
        {"region": "us-east-1", "model": "amazon.titan-text-express-v1"}
    )
    assert titan.count_tokens(TEXT) == heuristic_token_count(
        TEXT, model="amazon.titan-text-express-v1"
    )

    mistral = BedrockProvider(
        {"region": "us-east-1", "model": "mistral.mixtral-8x7b-instruct-v0:1"}
    )
    assert mistral.count_tokens(TEXT) == heuristic_token_count(TEXT, 3.2)


@pytest.mark.parametrize(
    ("module", "cls", "config"),
    [
        ("metis.providers.ollama", "OllamaProvider", {"model": "llama3:8b"}),
        (
            "metis.providers.vllm",
            "VLLMProvider",
            {"model": "mistralai/Mixtral-8x7B", "base_url": "http://x"},
        ),
        ("metis.providers.llamacpp", "LlamaCppProvider", {"model": "qwen2.5-coder"}),
    ],
)
def test_local_oai_compatible_providers_use_model_family_heuristic(module, cls, config):
    import importlib

    provider_cls = getattr(importlib.import_module(module), cls)
    provider = provider_cls(config)
    assert provider.count_tokens(TEXT) == heuristic_token_count(
        TEXT, model=config["model"]
    )


def test_gemini_provider_inherits_base_heuristic():
    pytest.importorskip("langchain_google_genai")
    from metis.providers.gemini import GeminiProvider

    provider = GeminiProvider({"api_key": "k", "model": "gemini-2.0-flash"})
    assert provider.count_tokens(TEXT) == heuristic_token_count(TEXT)
