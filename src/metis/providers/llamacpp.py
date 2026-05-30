# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""
llama.cpp server provider.

llama.cpp's HTTP server exposes OpenAI-compatible endpoints
(/v1/chat/completions, /v1/responses, /v1/embeddings, /v1/models, /v1/completions)
and can be used as a drop-in replacement for OpenAI-compatible providers.

See: https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md
"""

from __future__ import annotations

import logging

from metis.providers.openai_compatible import OpenAICompatibleProvider
from metis.providers.registry import register_provider

logger = logging.getLogger(__name__)


class LlamaCppProvider(OpenAICompatibleProvider):
    """Provider for llama.cpp HTTP server.

    The server is OpenAI-API compatible and supports:
    - /v1/chat/completions  (chat completions)
    - /v1/responses         (responses API, converted to chat completions)
    - /v1/completions       (legacy completions)
    - /v1/embeddings        (embeddings, requires pooling != none)
    - /v1/models            (model info with context window in meta.n_ctx_train)

    Default base URL is http://localhost:8080/v1.
    """

    DEFAULT_BASE_URL = "http://localhost:8080/v1"
    DEFAULT_API_KEY = "sk-no-key-required"

    def __init__(self, config):
        super().__init__(config)

        # Default base URL if not configured
        if not self.base_url:
            self.base_url = self.DEFAULT_BASE_URL
            logger.info(
                "llama.cpp base URL not configured, defaulting to %s",
                self.DEFAULT_BASE_URL,
            )

        # Require a query model
        if not self.query_model:
            raise ValueError(
                "llama.cpp provider requires a default query model "
                "(set 'model' or 'llama_query_model' in llm_provider config)"
            )

        # Require embedding models
        if not self.code_embedding_model or not self.docs_embedding_model:
            raise ValueError(
                "llama.cpp provider requires embedding models to be configured "
                "(set 'code_embedding_model' and 'docs_embedding_model')"
            )

        # The llama.cpp server accepts any API key string; use a placeholder
        if not self.api_key:
            self.api_key = self.DEFAULT_API_KEY


register_provider("llamacpp", LlamaCppProvider)
