# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from functools import cached_property
from typing import Any, Unpack, cast

from anthropic import AnthropicBedrockMantle
from anthropic import AsyncAnthropicBedrockMantle
from langchain_anthropic import ChatAnthropic
from langchain_core.callbacks import Callbacks
from langchain_openai import OpenAIEmbeddings
from llama_index.core.callbacks import CallbackManager
from pydantic import Field
from pydantic import SecretStr

from metis.providers.base import ChatModelOptions
from metis.providers.base import LLMProvider
from metis.providers.embedding_adapter import LangChainEmbeddingAdapter
from metis.providers.registry import register_provider


class ChatBedrockMantle(ChatAnthropic):
    """Anthropic chat model transported through Amazon Bedrock Mantle."""

    aws_region: str | None = None
    aws_profile: str | None = None
    aws_access_key: str | None = None
    aws_secret_key: str | None = None
    aws_session_token: str | None = None
    bedrock_base_url: str | None = Field(default=None, alias="bedrock_base_url")

    @property
    def _llm_type(self) -> str:
        return "anthropic-bedrock-mantle-chat"

    def _bedrock_client_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {
            "aws_region": self.aws_region,
            "aws_profile": self.aws_profile,
            "aws_access_key": self.aws_access_key,
            "aws_secret_key": self.aws_secret_key,
            "aws_session_token": self.aws_session_token,
            "max_retries": self.max_retries,
        }
        if self.bedrock_base_url:
            params["base_url"] = self.bedrock_base_url
        if self.default_headers:
            params["default_headers"] = self.default_headers
        if self.default_request_timeout is None or self.default_request_timeout > 0:
            params["timeout"] = self.default_request_timeout
        return {key: value for key, value in params.items() if value is not None}

    @cached_property
    def _client(self) -> AnthropicBedrockMantle:
        return AnthropicBedrockMantle(**self._bedrock_client_params())

    @cached_property
    def _async_client(self) -> AsyncAnthropicBedrockMantle:
        return AsyncAnthropicBedrockMantle(**self._bedrock_client_params())


class BedrockMantleProvider(LLMProvider):
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.embedding_api_key = config.get("embedding_api_key")
        self.query_model = config.get("llama_query_model") or config.get("model")
        self.supports_temperature = bool(config.get("supports_temperature", False))
        self.temperature = (
            float(config.get("llama_query_temperature", 0.0))
            if self.supports_temperature
            else None
        )
        self.max_tokens = int(config.get("llama_query_max_tokens", 3072))
        self.aws_region = config.get("aws_region")
        self.aws_profile = config.get("aws_profile")
        self.aws_access_key = config.get("aws_access_key_id") or None
        self.aws_secret_key = config.get("aws_secret_access_key") or None
        self.aws_session_token = config.get("aws_session_token") or None
        self.base_url = config.get("bedrock_base_url") or config.get("base_url")
        self.default_headers = dict(config.get("default_headers", {}))

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
                "Bedrock Mantle provider embeddings require "
                "llm_provider.embedding_api_key, llm_provider.embedding_api_key_env, "
                "or OPENAI_API_KEY."
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
    ) -> ChatBedrockMantle:
        requested_model = kwargs.pop("model", None)
        positional_model = args[0] if args else None
        model_name = requested_model or positional_model or self.query_model
        if not model_name:
            raise ValueError("Missing chat model configuration")

        params: dict[str, Any] = {
            "model": model_name,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "aws_region": self.aws_region,
            "aws_profile": self.aws_profile,
        }
        if self.aws_access_key and self.aws_secret_key:
            params["aws_access_key"] = self.aws_access_key
            params["aws_secret_key"] = self.aws_secret_key
            if self.aws_session_token:
                params["aws_session_token"] = self.aws_session_token
        if self.base_url:
            params["bedrock_base_url"] = self.base_url
        if self.default_headers:
            params["default_headers"] = self.default_headers
        if "top_p" in kwargs and "temperature" in kwargs:
            raise ValueError(
                "Bedrock Mantle chat model accepts either temperature or top_p, not both."
            )
        if self.supports_temperature:
            if "temperature" in kwargs:
                params["temperature"] = kwargs["temperature"]
            elif "top_p" not in kwargs and self.temperature is not None:
                params["temperature"] = self.temperature
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

        return ChatBedrockMantle(**cast(dict[str, Any], params))


register_provider("bedrock_mantle", BedrockMantleProvider)
