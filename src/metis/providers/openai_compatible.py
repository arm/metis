# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Required, TypedDict, cast

from langchain_core.callbacks import Callbacks
from langchain_openai import ChatOpenAI
from langchain_openai import OpenAIEmbeddings
from llama_index.core.callbacks import CallbackManager
from pydantic import SecretStr

from metis.providers.base import ChatProvider
from metis.providers.base import EmbeddingProvider
from metis.providers.embedding_adapter import LangChainEmbeddingAdapter


class OpenAICompatibleChatConfig(TypedDict, total=False):
    api_key: str
    base_url: str
    default_headers: Mapping[str, str]
    model: Required[str]


class OpenAICompatibleEmbeddingConfig(TypedDict, total=False):
    api_key: str
    base_url: str
    default_headers: Mapping[str, str]
    code_embedding_model: Required[str]
    docs_embedding_model: Required[str]
    code_extra_kwargs: Mapping[str, object]
    docs_extra_kwargs: Mapping[str, object]


class OpenAICompatibleChatProvider(ChatProvider):
    DEFAULT_BASE_URL: str | None = None
    DEFAULT_API_KEY: str | None = None

    def __init__(self, config: OpenAICompatibleChatConfig) -> None:
        self.config = config
        self.api_key = config.get("api_key") or self.DEFAULT_API_KEY
        self.base_url = config.get("base_url") or self.DEFAULT_BASE_URL
        self.default_headers = dict(config.get("default_headers") or {})
        self.default_model = config.get("model")

        if not self.default_model:
            raise ValueError("Missing chat model configuration")

    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: object,
    ) -> ChatOpenAI:
        requested_model = kwargs.pop("model", None)
        positional_model = args[0] if args else None
        model_name = requested_model or positional_model or self.default_model
        if not model_name:
            raise ValueError("Missing chat model configuration")

        params: dict[str, object] = {
            "model": model_name,
            "use_responses_api": True,
        }
        temperature = kwargs.get("temperature")
        if temperature is not None:
            params["temperature"] = float(temperature)
        max_tokens = kwargs.get("max_tokens")
        if max_tokens is not None:
            params["max_tokens"] = int(max_tokens)
        if self.api_key:
            params["api_key"] = self.api_key
        if self.base_url:
            params["openai_api_base"] = self.base_url
        if self.default_headers:
            params["default_headers"] = self.default_headers
        if callbacks is not None:
            params["callbacks"] = callbacks

        for optional_key in (
            "timeout",
            "request_timeout",
            "max_retries",
            "frequency_penalty",
            "presence_penalty",
            "seed",
            "logit_bias",
            "reasoning_effort",
            "verbosity",
        ):
            if optional_key in kwargs:
                params[optional_key] = kwargs[optional_key]

        return ChatOpenAI(**cast(dict[str, Any], params))


class OpenAICompatibleEmbeddingProvider(EmbeddingProvider):
    DEFAULT_BASE_URL: str | None = None
    DEFAULT_API_KEY: str | None = None

    def __init__(self, config: OpenAICompatibleEmbeddingConfig) -> None:
        self.config = config
        self.api_key = config.get("api_key") or self.DEFAULT_API_KEY
        self.base_url = config.get("base_url") or self.DEFAULT_BASE_URL
        self.default_headers = dict(config.get("default_headers") or {})
        self.code_embedding_model = config.get("code_embedding_model")
        self.docs_embedding_model = config.get("docs_embedding_model")
        self.code_extra_kwargs = dict(config.get("code_extra_kwargs", {}))
        self.docs_extra_kwargs = dict(config.get("docs_extra_kwargs", {}))

        if not self.code_embedding_model or not self.docs_embedding_model:
            raise ValueError(
                "Missing embedding model configuration "
                "(set 'code_embedding_model' and 'docs_embedding_model')"
            )

    def get_embed_model_code(
        self, *, callback_manager: CallbackManager | None = None
    ) -> LangChainEmbeddingAdapter:
        return self._build_embedding_model(
            self.code_embedding_model,
            self.code_extra_kwargs,
            callback_manager=callback_manager,
        )

    def get_embed_model_docs(
        self, *, callback_manager: CallbackManager | None = None
    ) -> LangChainEmbeddingAdapter:
        return self._build_embedding_model(
            self.docs_embedding_model,
            self.docs_extra_kwargs,
            callback_manager=callback_manager,
        )

    def _build_embedding_model(
        self,
        model_name: str,
        extra_kwargs: dict[str, object],
        callback_manager: CallbackManager | None = None,
    ) -> LangChainEmbeddingAdapter:
        params: dict[str, object] = {"model": model_name}
        if self.api_key:
            params["api_key"] = SecretStr(self.api_key)
        if self.base_url:
            params["base_url"] = self.base_url
        if self.default_headers:
            params["default_headers"] = self.default_headers
        if extra_kwargs:
            params.update(extra_kwargs)

        client = OpenAIEmbeddings(**cast(dict[str, Any], params))
        return LangChainEmbeddingAdapter(
            client,
            model_name=model_name,
            callback_manager=callback_manager,
        )
