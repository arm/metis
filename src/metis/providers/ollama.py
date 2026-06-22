# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""
Ollama provider.

Ollama's /v1 API is compatible with OpenAI's chat and embedding APIs.
"""

from __future__ import annotations

import logging

from metis.providers.openai_compatible import OpenAICompatibleChatProvider
from metis.providers.openai_compatible import OpenAICompatibleEmbeddingProvider
from metis.providers.config import ProviderConfigSpec
from metis.utils import count_tokens as count_tokens_for_model

logger = logging.getLogger(__name__)


class OllamaProvider(OpenAICompatibleChatProvider):
    """Provider for Ollama's OpenAI-compatible API.

    Default base URL is http://localhost:11434/v1.
    """

    DEFAULT_BASE_URL = "http://localhost:11434/v1"
    DEFAULT_API_KEY = "default-key"
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="Ollama",
        required_keys=("model",),
        copy_keys=("base_url", "default_headers", "model"),
    )

    def __init__(self, config):
        if not config.get("api_key"):
            logger.warning(
                "Langchain Ollama integration requires an non-empty api_key, "
                "using a default."
            )
        super().__init__(config)

    def count_tokens(self, text: str) -> int:
        return count_tokens_for_model(text, self.default_model)


class OllamaEmbeddingProvider(OpenAICompatibleEmbeddingProvider):
    DEFAULT_BASE_URL = OllamaProvider.DEFAULT_BASE_URL
    DEFAULT_API_KEY = OllamaProvider.DEFAULT_API_KEY
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="Ollama embeddings",
        required_keys=("code_embedding_model", "docs_embedding_model"),
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
