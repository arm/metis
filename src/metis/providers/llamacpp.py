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
        super().__init__(
            config,
            default_base_url=self.DEFAULT_BASE_URL,
            default_api_key=self.DEFAULT_API_KEY,
        )

        if (
            not config.get("openai_api_base")
            and not config.get("api_base")
            and not config.get("base_url")
        ):
            logger.info(
                "llama.cpp base URL not configured, defaulting to %s",
                self.DEFAULT_BASE_URL,
            )


register_provider("llamacpp", LlamaCppProvider)
