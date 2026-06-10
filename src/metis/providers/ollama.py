# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""
Ollama provider.

Ollama's /v1 API is compatible with OpenAI's chat and embedding APIs.
"""

from __future__ import annotations

import logging

from metis.providers.openai_compatible import OpenAICompatibleProvider
from metis.providers.registry import register_provider

logger = logging.getLogger(__name__)


class OllamaProvider(OpenAICompatibleProvider):
    """Provider for Ollama's OpenAI-compatible API.

    Default base URL is http://localhost:11434/v1.
    """

    DEFAULT_BASE_URL = "http://localhost:11434/v1"
    DEFAULT_API_KEY = "default-key"

    def __init__(self, config):
        if not config.get("llm_api_key"):
            logger.warning(
                "Langchain Ollama integration requires an non-empty api_key, "
                "using a default."
            )
        super().__init__(
            config,
            default_base_url=self.DEFAULT_BASE_URL,
            default_api_key=self.DEFAULT_API_KEY,
        )


register_provider("ollama", OllamaProvider)
