# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Unpack, cast

from langchain_anthropic import ChatAnthropic
from langchain_core.callbacks import Callbacks
from langchain_openai import OpenAIEmbeddings
from llama_index.core.callbacks import CallbackManager
from pydantic import SecretStr

from metis.providers.base import ChatModelOptions, LLMProvider
from metis.providers.embedding_adapter import LangChainEmbeddingAdapter
from metis.providers.registry import register_provider


class AnthropicProvider(LLMProvider):
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.api_key = config.get("llm_api_key")
        self.embedding_api_key = config.get("embedding_api_key")
        self.query_model = config.get("llama_query_model") or config.get("model")
        self.supports_temperature = bool(config.get("supports_temperature", True))
        self.temperature = float(config.get("llama_query_temperature", 0.0))
        self.max_tokens = int(config.get("llama_query_max_tokens", 3072))
        self.base_url = config.get("anthropic_api_url") or config.get("base_url")

        self.code_embedding_model = config.get("code_embedding_model")
        self.docs_embedding_model = config.get("docs_embedding_model")
        self.code_embedding_extra_kwargs = dict(
            config.get("code_embedding_extra_kwargs", {})
        )
        self.docs_embedding_extra_kwargs = dict(
            config.get("docs_embedding_extra_kwargs", {})
        )
        self.embedding_api_base = config.get("embedding_api_base") or config.get(
            "embedding_base_url"
        )
        self.embedding_default_headers = dict(
            config.get("embedding_default_headers", {})
        )

    def _require_embedding_api_key(self) -> str:
        if not self.embedding_api_key:
            raise ValueError(
                "Anthropic provider embeddings require llm_provider.embedding_api_key, "
                "llm_provider.embedding_api_key_env, or OPENAI_API_KEY."
            )
        return self.embedding_api_key

    def get_embed_model_code(
        self, *, callback_manager: CallbackManager | None = None
    ) -> LangChainEmbeddingAdapter:
        return self._build_embedding_model(
            self.code_embedding_model,
            self.code_embedding_extra_kwargs,
            "code_embedding_model",
            callback_manager=callback_manager,
        )

    def get_embed_model_docs(
        self, *, callback_manager: CallbackManager | None = None
    ) -> LangChainEmbeddingAdapter:
        return self._build_embedding_model(
            self.docs_embedding_model,
            self.docs_embedding_extra_kwargs,
            "docs_embedding_model",
            callback_manager=callback_manager,
        )

    def _build_embedding_model(
        self,
        model_name: str | None,
        extra_kwargs: dict[str, object],
        config_key: str,
        callback_manager: CallbackManager | None = None,
    ) -> LangChainEmbeddingAdapter:
        if not model_name:
            raise ValueError(f"Missing '{config_key}' in configuration")

        params: dict[str, object] = {
            "model": model_name,
            "api_key": SecretStr(self._require_embedding_api_key()),
        }
        if self.embedding_api_base:
            params["base_url"] = self.embedding_api_base
        if self.embedding_default_headers:
            params["default_headers"] = self.embedding_default_headers
        if extra_kwargs:
            params.update(extra_kwargs)

        client = OpenAIEmbeddings(**cast(dict[str, Any], params))
        return LangChainEmbeddingAdapter(
            client,
            model_name=model_name,
            callback_manager=callback_manager,
        )

    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: Unpack[ChatModelOptions],
    ) -> ChatAnthropic:
        requested_model = kwargs.pop("model", None)
        positional_model = args[0] if args else None
        model_name = requested_model or positional_model or self.query_model
        if not model_name:
            raise ValueError("Missing chat model configuration")
        if not self.api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable is required for "
                "Anthropic provider but not set."
            )

        params: dict[str, Any] = {
            "model": model_name,
            "api_key": self.api_key,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }
        if "top_p" in kwargs and "temperature" in kwargs:
            raise ValueError(
                "Anthropic chat model accepts either temperature or top_p, not both."
            )
        if "temperature" in kwargs:
            params["temperature"] = kwargs["temperature"]
        elif "top_p" not in kwargs and self.supports_temperature:
            params["temperature"] = self.temperature
        if self.base_url:
            params["base_url"] = self.base_url
        if callbacks is not None:
            params["callbacks"] = callbacks

        for optional_key in (
            "timeout",
            "default_request_timeout",
            "max_retries",
            "top_k",
            "top_p",
            "stop_sequences",
        ):
            if optional_key in kwargs:
                params[optional_key] = kwargs[optional_key]

        return ChatAnthropic(**cast(dict[str, Any], params))


register_provider("anthropic", AnthropicProvider)
