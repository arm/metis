# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

import metis.providers.registry as registry
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


def test_registry_loads_source_tree_providers_without_installed_entry_points(
    monkeypatch,
):
    class _NoEntryPoints:
        def select(self, **_kwargs):
            return []

    monkeypatch.setattr(registry.metadata, "entry_points", lambda: _NoEntryPoints())
    monkeypatch.setattr(registry, "_CHAT_PROVIDERS", {})
    monkeypatch.setattr(registry, "_EMBEDDING_PROVIDERS", {})
    monkeypatch.setattr(registry, "_PROVIDER_LOADERS", {})
    monkeypatch.setattr(registry, "_PROVIDER_LOADERS_DISCOVERED", False)

    assert get_chat_provider("openai").__name__ == "OpenAIProvider"
    assert get_embedding_provider("openai").__name__ == "OpenAIEmbeddingProvider"
