# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging

from metis.providers.openai_compatible import OpenAICompatibleChatProvider
from metis.providers.openai_compatible import OpenAICompatibleEmbeddingProvider
from metis.providers.config import ApiKeySources
from metis.providers.config import ProviderConfigSpec


logger = logging.getLogger(__name__)


class VLLMProvider(OpenAICompatibleChatProvider):
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

        if not self.api_key:
            logger.debug("vLLM provider running without API key")


class VLLMEmbeddingProvider(OpenAICompatibleEmbeddingProvider):
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
