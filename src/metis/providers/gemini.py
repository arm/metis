# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Unpack, cast

from langchain_core.callbacks import Callbacks
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from llama_index.core.callbacks import CallbackManager

from metis.providers.base import ChatModelOptions
from metis.providers.base import GeminiProviderConfig
from metis.providers.base import LLMProvider
from metis.providers.embedding_adapter import LangChainEmbeddingAdapter
from metis.providers.registry import register_provider


class GeminiProvider(LLMProvider):
    def __init__(self, config: GeminiProviderConfig) -> None:
        self.config = config
        self.api_key = config.get("llm_api_key")
        self.query_model = config.get("llama_query_model") or config.get("model")
        self.temperature = float(config.get("llama_query_temperature", 0.0))
        self.max_tokens = int(config.get("llama_query_max_tokens", 3072))
        self.reasoning_effort = config.get("llama_query_reasoning_effort")

        self.code_embedding_model = config.get("code_embedding_model")
        self.docs_embedding_model = config.get("docs_embedding_model")
        self.code_embedding_extra_kwargs = dict(
            config.get("code_embedding_extra_kwargs", {})
        )
        self.docs_embedding_extra_kwargs = dict(
            config.get("docs_embedding_extra_kwargs", {})
        )

        self.base_url = config.get("gemini_api_base")
        self.additional_headers = dict(config.get("gemini_additional_headers", {}))
        self.project = config.get("gemini_project")
        self.location = config.get("gemini_location")
        self.vertexai = config.get("gemini_vertexai")
        self.client_args = dict(config.get("gemini_client_args", {}))

        if not self.api_key and not self.vertexai:
            raise ValueError(
                "GOOGLE_API_KEY or GEMINI_API_KEY environment variable is required "
                "for Gemini provider but not set."
            )
        if not self.query_model:
            raise ValueError(
                "Missing query model configuration "
                "(set 'model' or 'llama_query_model' in llm_provider config)"
            )

    def _common_params(self) -> dict[str, object]:
        params: dict[str, object] = {}
        if self.api_key:
            params["api_key"] = self.api_key
        if self.base_url:
            params["base_url"] = self.base_url
        if self.additional_headers:
            params["additional_headers"] = self.additional_headers
        if self.project:
            params["project"] = self.project
        if self.location:
            params["location"] = self.location
        if self.vertexai is not None:
            params["vertexai"] = self.vertexai
        if self.client_args:
            params["client_args"] = self.client_args
        return params

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

        params = {
            "model": model_name,
            **self._common_params(),
            **extra_kwargs,
        }
        client = GoogleGenerativeAIEmbeddings(**cast(dict[str, Any], params))
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
    ) -> ChatGoogleGenerativeAI:
        requested_model = kwargs.pop("model", None)
        positional_model = args[0] if args else None
        model_name = requested_model or positional_model or self.query_model
        if not model_name:
            raise ValueError("Missing chat model configuration")

        response_format = kwargs.pop("response_format", None)
        params: dict[str, object] = {
            "model": model_name,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            **self._common_params(),
        }
        if callbacks is not None:
            params["callbacks"] = callbacks

        if (
            response_format
            and response_format.get("type") == "json_object"
            and "response_mime_type" not in kwargs
        ):
            params["response_mime_type"] = "application/json"

        reasoning_effort = kwargs.get("reasoning_effort", self.reasoning_effort)
        if (
            "thinking_level" not in kwargs
            and isinstance(reasoning_effort, str)
            and reasoning_effort in {"minimal", "low", "medium", "high"}
        ):
            params["thinking_level"] = reasoning_effort

        for optional_key in (
            "timeout",
            "max_retries",
            "top_p",
            "top_k",
            "stop",
            "n",
            "safety_settings",
            "thinking_budget",
            "thinking_level",
            "include_thoughts",
            "response_mime_type",
            "response_schema",
            "seed",
        ):
            if optional_key in kwargs:
                params[optional_key] = kwargs[optional_key]

        return ChatGoogleGenerativeAI(**cast(dict[str, Any], params))


register_provider("gemini", GeminiProvider)
