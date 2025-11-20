# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Dict

from langchain_openai import ChatOpenAI
from llama_index.embeddings.openai import (
    OpenAIEmbedding,
    OpenAIEmbeddingModelType,
)
from llama_index.llms.openai import OpenAI as LlamaOpenAI

try:
    from llama_index.llms.openai_like import OpenAILike as LlamaOpenAILike
except (ImportError, ModuleNotFoundError):
    LlamaOpenAILike = None

from metis.providers.base import LLMProvider

_ALLOWED_OPENAI_EMBED_MODELS = {member.value for member in OpenAIEmbeddingModelType}


class OpenAICompatibleProvider(LLMProvider):

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_key = config.get("llm_api_key")
        self.base_url = (
            config.get("openai_api_base")
            or config.get("api_base")
            or config.get("base_url")
        )
        self.default_headers = (
            config.get("openai_default_headers") or config.get("default_headers") or {}
        )
        self.query_model = config.get("llama_query_model") or config.get("model")
        self.temperature = config.get("llama_query_temperature", 0.0)
        self.max_tokens = config.get("llama_query_max_tokens", 512)
        self.context_window = config.get("llama_query_context_window") or config.get(
            "max_token_length"
        )
        self.code_embedding_model = config.get("code_embedding_model")
        self.docs_embedding_model = config.get("docs_embedding_model")
        self.code_embedding_extra_kwargs = config.get("code_embedding_extra_kwargs", {})
        self.docs_embedding_extra_kwargs = config.get("docs_embedding_extra_kwargs", {})

    def get_embed_model_code(self):
        return self._build_embedding_model(
            self.code_embedding_model,
            self.code_embedding_extra_kwargs,
            "code_embedding_model",
        )

    def get_embed_model_docs(self):
        return self._build_embedding_model(
            self.docs_embedding_model,
            self.docs_embedding_extra_kwargs,
            "docs_embedding_model",
        )

    def _build_embedding_model(
        self,
        model_name: str | None,
        extra_kwargs: Dict[str, Any],
        config_key: str,
    ):
        if not model_name:
            raise ValueError(f"Missing '{config_key}' in configuration")

        params: Dict[str, Any] = {}
        params["model"] = (
            model_name
            if model_name in _ALLOWED_OPENAI_EMBED_MODELS
            else OpenAIEmbeddingModelType.TEXT_EMBED_ADA_002.value
        )
        if self.api_key:
            params["api_key"] = self.api_key
        if self.base_url:
            params["api_base"] = self.base_url
        if self.default_headers:
            params["default_headers"] = self.default_headers
        if extra_kwargs:
            params.update(extra_kwargs)

        embed = OpenAIEmbedding(**params)
        if model_name not in _ALLOWED_OPENAI_EMBED_MODELS:
            embed._query_engine = model_name
            embed._text_engine = model_name
            embed.model_name = model_name
        return embed

    def get_chat_model(self, model: str | None = None, **kwargs):
        model_name = model or self.query_model
        if not model_name:
            raise ValueError("Missing chat model configuration")

        params: Dict[str, Any] = {
            "model": model_name,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }

        if self.api_key:
            params["api_key"] = self.api_key
        if self.base_url:
            params["openai_api_base"] = self.base_url
        if self.default_headers:
            params["default_headers"] = self.default_headers

        for optional_key in (
            "timeout",
            "request_timeout",
            "max_retries",
            "frequency_penalty",
            "presence_penalty",
            "seed",
            "logit_bias",
        ):
            if optional_key in kwargs:
                params[optional_key] = kwargs[optional_key]

        return ChatOpenAI(**params)

    def get_query_engine_class(self):
        if self._should_use_openai_like():
            if LlamaOpenAILike is None:
                raise ModuleNotFoundError(
                    "llama-index-llms-openai-like is required for OpenAI-compatible "
                    "providers targeting custom endpoints."
                )
            return LlamaOpenAILike
        return LlamaOpenAI

    def get_query_model_kwargs(self):
        if not self.query_model:
            raise ValueError("Missing chat model configuration for query engine")

        params: Dict[str, Any] = {
            "model": self.query_model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if self.api_key:
            params["api_key"] = self.api_key
        if self.base_url:
            params["api_base"] = self.base_url
        if self.default_headers:
            params["default_headers"] = self.default_headers
        if self._should_use_openai_like():
            params["context_window"] = self._resolve_context_window()
            params.setdefault("is_chat_model", True)
            params.setdefault("is_function_calling_model", True)

        return params

    def _should_use_openai_like(self):
        forced = bool(self.config.get("force_openai_like"))
        if forced:
            return True
        if not self.base_url:
            return False
        normalized = str(self.base_url).strip().lower()
        # Treat the official OpenAI endpoint as the only case where we keep the default class.
        return "api.openai.com" not in normalized

    def _resolve_context_window(self):
        candidates = [
            self.context_window,
            self.config.get("max_token_length"),
            8192,
        ]
        for value in candidates:
            try:
                ivalue = int(value)
                if ivalue > 0:
                    return ivalue
            except (TypeError, ValueError):
                continue
        return 8192
