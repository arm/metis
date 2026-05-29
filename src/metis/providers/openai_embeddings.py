# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from llama_index.embeddings.openai import (
    OpenAIEmbedding,
    OpenAIEmbeddingModelType,
)

_ALLOWED_OPENAI_EMBED_MODELS = {member.value for member in OpenAIEmbeddingModelType}


def build_openai_compatible_embedding_model(
    model_name: str | None,
    extra_kwargs: dict[str, Any] | None,
    config_key: str,
    *,
    api_key: str | None = None,
    api_base: str | None = None,
    default_headers: dict[str, str] | None = None,
    callback_manager=None,
):
    if not model_name:
        raise ValueError(f"Missing '{config_key}' in configuration")

    params: dict[str, Any] = {
        "model": (
            model_name
            if model_name in _ALLOWED_OPENAI_EMBED_MODELS
            else OpenAIEmbeddingModelType.TEXT_EMBED_ADA_002.value
        )
    }
    if api_key:
        params["api_key"] = api_key
    if api_base:
        params["api_base"] = api_base
    if default_headers:
        params["default_headers"] = default_headers
    if callback_manager is not None:
        params["callback_manager"] = callback_manager
    if extra_kwargs:
        params.update(extra_kwargs)

    embed = OpenAIEmbedding(**params)
    if model_name not in _ALLOWED_OPENAI_EMBED_MODELS:
        embed._query_engine = model_name
        embed._text_engine = model_name
        embed.model_name = model_name
    return embed
