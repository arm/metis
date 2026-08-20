# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import patch

import pytest

from metis.providers.registry import get_chat_provider
from metis.providers.registry import get_embedding_provider


@pytest.mark.parametrize(
    ("name", "class_name", "module_name"),
    [
        ("openai", "OpenAIProvider", "metis.providers.openai"),
        (
            "azure_openai",
            "AzureOpenAIProvider",
            "metis.providers.azure_openai",
        ),
        ("vllm", "VLLMProvider", "metis.providers.vllm"),
        ("ollama", "OllamaProvider", "metis.providers.ollama"),
        ("llamacpp", "LlamaCppProvider", "metis.providers.llamacpp"),
        ("anthropic", "AnthropicProvider", "metis.providers.anthropic"),
        ("gemini", "GeminiProvider", "metis.providers.gemini"),
        ("bedrock", "BedrockProvider", "metis.providers.bedrock"),
        ("bedrock_mantle", "BedrockMantleProvider", "metis.providers.bedrock_mantle"),
    ],
)
def test_registry_loads_chat_providers(name, class_name, module_name):
    provider_cls = get_chat_provider(name)

    assert provider_cls.__name__ == class_name
    assert provider_cls.__module__ == module_name


@pytest.mark.parametrize(
    ("name", "class_name", "module_name"),
    [
        ("openai", "OpenAIEmbeddingProvider", "metis.providers.openai"),
        (
            "azure_openai",
            "AzureOpenAIEmbeddingProvider",
            "metis.providers.azure_openai",
        ),
        ("vllm", "VLLMEmbeddingProvider", "metis.providers.vllm"),
        ("ollama", "OllamaEmbeddingProvider", "metis.providers.ollama"),
        ("llamacpp", "LlamaCppEmbeddingProvider", "metis.providers.llamacpp"),
        ("bedrock", "BedrockEmbeddingProvider", "metis.providers.bedrock"),
    ],
)
def test_registry_loads_embedding_providers(name, class_name, module_name):
    provider_cls = get_embedding_provider(name)

    assert provider_cls.__name__ == class_name
    assert provider_cls.__module__ == module_name


@pytest.mark.parametrize("name", ["anthropic", "bedrock_mantle", "gemini"])
def test_registry_rejects_embedding_for_chat_only_providers(name):
    with pytest.raises(ValueError, match="Unsupported embedding provider"):
        get_embedding_provider(name)


@pytest.mark.parametrize("get_provider", [get_chat_provider, get_embedding_provider])
def test_registry_reuses_loaded_provider(get_provider) -> None:
    provider_cls = get_provider("openai")

    with patch("metis.providers.registry.import_module") as import_module:
        assert get_provider("OPENAI") is provider_cls
    import_module.assert_not_called()
