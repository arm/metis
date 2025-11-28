# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging

from metis.providers.openai_compatible import OpenAICompatibleProvider
from metis.providers.registry import register_provider


logger = logging.getLogger(__name__)


class OllamaProvider(OpenAICompatibleProvider):

    def __init__(self, config):
        super().__init__(config)
        if not self.base_url:
            self.base_url = "http://localhost:11434/v1"
        if not self.query_model:
            raise ValueError("Ollama provider requires a default query model")
        if not self.code_embedding_model or not self.docs_embedding_model:
            raise ValueError(
                "Ollama provider requires embedding models to be configured"
            )
        if not config.get("force_openai_like"):
            logger.debug("Force-enabling OpenAI-like mode for Ollama provider")
            self.config["force_openai_like"] = True
        if not config.get("llm_api_key"):
            logger.warning("Langchain Ollama integration requires an non-empty api_key, using a default.")
            self.api_key = "default-key"

register_provider("ollama", OllamaProvider)
