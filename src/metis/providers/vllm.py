# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.providers.openai_compatible import OpenAICompatibleChatProvider
from metis.providers.openai_compatible import OpenAICompatibleEmbeddingProvider
from metis.providers.config import ApiKeySources
from metis.providers.config import ProviderConfigSpec
from metis.utils import count_tokens as count_tokens_for_model


class VLLMProvider(OpenAICompatibleChatProvider):
    DEFAULT_API_KEY = "sk-no-key-required"
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="vLLM",
        required_keys=("base_url", "model"),
        api_key=ApiKeySources(required=False, env_vars=("VLLM_API_KEY",)),
        copy_keys=("base_url", "default_headers", "model"),
    )

    def __init__(self, config):
        super().__init__(config)
        if not self.base_url:
            raise ValueError("vLLM provider requires 'base_url' to be configured")

    def count_tokens(self, text: str, model: str | None = None) -> int:
        return count_tokens_for_model(text, model or self.default_model)


class VLLMEmbeddingProvider(OpenAICompatibleEmbeddingProvider):
    DEFAULT_API_KEY = VLLMProvider.DEFAULT_API_KEY
    DEFAULT_CHECK_EMBEDDING_CTX_LENGTH = False
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="vLLM embeddings",
        required_keys=("base_url", "code_embedding_model", "docs_embedding_model"),
        api_key=ApiKeySources(required=False, env_vars=("VLLM_API_KEY",)),
        copy_keys=(
            "base_url",
            "default_headers",
            "code_embedding_model",
            "docs_embedding_model",
            "code_extra_kwargs",
            "docs_extra_kwargs",
        ),
    )

    def __init__(self, config):
        super().__init__(config)
        if not self.base_url:
            raise ValueError("vLLM embeddings require 'base_url' to be configured")
