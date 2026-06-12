# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.providers.openai_compatible import OpenAICompatibleChatProvider
from metis.providers.openai_compatible import OpenAICompatibleEmbeddingProvider
from metis.providers.config import ApiKeySources
from metis.providers.config import ProviderConfigSpec

import logging

logger = logging.getLogger(__name__)


class OpenAIProvider(OpenAICompatibleChatProvider):
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="OpenAI",
        required_keys=("model",),
        api_key=ApiKeySources(required=True, env_vars=("OPENAI_API_KEY",)),
        copy_keys=("base_url", "default_headers", "model"),
    )

    def __init__(self, config):
        super().__init__(config)
        if not self.api_key:
            raise ValueError(
                "OPENAI_API_KEY environment variable is required for OpenAI provider but not set."
            )


class OpenAIEmbeddingProvider(OpenAICompatibleEmbeddingProvider):
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="OpenAI embeddings",
        required_keys=("code_embedding_model", "docs_embedding_model"),
        api_key=ApiKeySources(required=True, env_vars=("OPENAI_API_KEY",)),
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
        if not self.api_key:
            raise ValueError(
                "OPENAI_API_KEY environment variable is required for OpenAI embeddings but not set."
            )
