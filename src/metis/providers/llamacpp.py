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

from metis.providers.openai_compatible import OpenAICompatibleChatProvider
from metis.providers.openai_compatible import OpenAICompatibleEmbeddingProvider
from metis.providers.config import ApiKeySources
from metis.providers.config import ProviderConfigSpec
from metis.utils import count_tokens as count_tokens_for_model

logger = logging.getLogger(__name__)


class LlamaCppProvider(OpenAICompatibleChatProvider):
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
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="llama.cpp",
        required_keys=("model",),
        api_key=ApiKeySources(required=False, env_vars=("LLAMACPP_API_KEY",)),
        copy_keys=("base_url", "default_headers", "model"),
    )

    def __init__(self, config):
        super().__init__(config)

        if not config.get("base_url"):
            logger.info(
                "llama.cpp base URL not configured, defaulting to %s",
                self.DEFAULT_BASE_URL,
            )

    def count_tokens(self, text: str) -> int:
        return count_tokens_for_model(text, self.default_model)


class LlamaCppEmbeddingProvider(OpenAICompatibleEmbeddingProvider):
    DEFAULT_BASE_URL = LlamaCppProvider.DEFAULT_BASE_URL
    DEFAULT_API_KEY = LlamaCppProvider.DEFAULT_API_KEY
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="llama.cpp embeddings",
        required_keys=("code_embedding_model", "docs_embedding_model"),
        api_key=ApiKeySources(required=False, env_vars=("LLAMACPP_API_KEY",)),
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
