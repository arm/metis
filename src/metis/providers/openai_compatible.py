# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Unpack, cast

from langchain_openai import ChatOpenAI
from langchain_core.callbacks import Callbacks
from llama_index.embeddings.openai import (
    OpenAIEmbedding,
    OpenAIEmbeddingModelType,
)
from llama_index.llms.openai import OpenAIResponses
from llama_index.core.callbacks import CallbackManager

from metis.providers.base import (
    ChatModelOptions,
    LLMProvider,
    OpenAICompatibleProviderConfig,
    QueryModelKwargs,
)

_ALLOWED_OPENAI_EMBED_MODELS = {member.value for member in OpenAIEmbeddingModelType}


class OpenAICompatibleProvider(LLMProvider):
    def __init__(
        self,
        config: OpenAICompatibleProviderConfig,
        *,
        default_base_url: str | None = None,
        default_api_key: str | None = None,
        force_openai_like: bool | None = None,
    ) -> None:
        self.config = config
        self.api_key = config.get("llm_api_key")
        self.base_url = (
            config.get("openai_api_base")
            or config.get("api_base")
            or config.get("base_url")
            or default_base_url
        )
        self.default_headers = dict(
            config.get("openai_default_headers") or config.get("default_headers") or {}
        )
        self.query_model = config.get("llama_query_model") or config.get("model")
        self.temperature = float(config.get("llama_query_temperature", 0.0))
        self.max_tokens = int(config.get("llama_query_max_tokens", 3072))
        self.reasoning_effort = config.get("llama_query_reasoning_effort")
        self.context_window = config.get("llama_query_context_window") or config.get(
            "max_token_length"
        )
        self.code_embedding_model = config.get("code_embedding_model")
        self.docs_embedding_model = config.get("docs_embedding_model")
        self.code_embedding_extra_kwargs = dict(
            config.get("code_embedding_extra_kwargs", {})
        )
        self.docs_embedding_extra_kwargs = dict(
            config.get("docs_embedding_extra_kwargs", {})
        )
        # Apply default API key when none provided
        if not self.api_key and default_api_key:
            self.api_key = default_api_key
        # Record force_openai_like preference so _uses_custom_openai_base can see it
        if force_openai_like is not None:
            self.config["force_openai_like"] = True

        # Validate required configuration
        if not self.query_model:
            raise ValueError(
                "Missing query model configuration "
                "(set 'model' or 'llama_query_model' in llm_provider config)"
            )
        if not self.code_embedding_model or not self.docs_embedding_model:
            raise ValueError(
                "Missing embedding model configuration "
                "(set 'code_embedding_model' and 'docs_embedding_model')"
            )

    def get_embed_model_code(
        self, *, callback_manager: CallbackManager | None = None
    ) -> OpenAIEmbedding:
        return self._build_embedding_model(
            self.code_embedding_model,
            self.code_embedding_extra_kwargs,
            "code_embedding_model",
            callback_manager=callback_manager,
        )

    def get_embed_model_docs(
        self, *, callback_manager: CallbackManager | None = None
    ) -> OpenAIEmbedding:
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
    ) -> OpenAIEmbedding:
        if not model_name:
            raise ValueError(f"Missing '{config_key}' in configuration")

        params: dict[str, object] = {}
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
        if callback_manager is not None:
            params["callback_manager"] = callback_manager
        if extra_kwargs:
            params.update(extra_kwargs)

        embed = OpenAIEmbedding(**cast(dict[str, Any], params))
        if model_name not in _ALLOWED_OPENAI_EMBED_MODELS:
            embed._query_engine = model_name
            embed._text_engine = model_name
            embed.model_name = model_name
        return embed

    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: Unpack[ChatModelOptions],
    ) -> ChatOpenAI:
        requested_model = kwargs.pop("model", None)
        positional_model = args[0] if args else None
        model_name = requested_model or positional_model or self.query_model
        if not model_name:
            raise ValueError("Missing chat model configuration")

        params: dict[str, object] = {
            "model": model_name,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "use_responses_api": True,
        }

        if self.api_key:
            params["api_key"] = self.api_key
        if self.base_url:
            params["openai_api_base"] = self.base_url
        if self.default_headers:
            params["default_headers"] = self.default_headers
        if callbacks is not None:
            params["callbacks"] = callbacks
        if self.reasoning_effort:
            params["reasoning_effort"] = self.reasoning_effort

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

        return ChatOpenAI(**cast(dict[str, Any], params))

    def get_query_engine_class(self) -> type[OpenAIResponses]:
        return OpenAIResponses

    def get_query_model_kwargs(
        self,
        *,
        callback_manager: CallbackManager | None = None,
        callbacks: Callbacks = None,
    ) -> QueryModelKwargs:
        if not self.query_model:
            raise ValueError("Missing chat model configuration for query engine")

        params: dict[str, object] = {
            "model": self.query_model,
            "temperature": self.temperature,
            "max_output_tokens": self.max_tokens,
        }
        if self.api_key:
            params["api_key"] = self.api_key
        if self.base_url:
            params["api_base"] = self.base_url
        if self.default_headers:
            params["default_headers"] = self.default_headers
        if callback_manager is not None:
            params["callback_manager"] = callback_manager
        if self.reasoning_effort:
            reasoning = {"effort": self.reasoning_effort}
            params["reasoning_options"] = reasoning
            params["additional_kwargs"] = {"reasoning": reasoning}
        if self._uses_custom_openai_base():
            params["context_window"] = self._resolve_context_window()

        return params

    def _uses_custom_openai_base(self) -> bool:
        forced = bool(self.config.get("force_openai_like"))
        if forced:
            return True
        if not self.base_url:
            return False
        normalized = str(self.base_url).strip().lower()
        # Official OpenAI endpoints can use model metadata; custom endpoints
        # need an explicit context window.
        return "api.openai.com" not in normalized

    def _resolve_context_window(self) -> int:
        candidates = [
            self.context_window,
            self.config.get("max_token_length"),
            8192,
        ]
        for value in candidates:
            if value is None:
                continue
            try:
                ivalue = int(value)
                if ivalue > 0:
                    return ivalue
            except (TypeError, ValueError):
                continue
        return 8192
