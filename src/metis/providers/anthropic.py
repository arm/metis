# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from langchain_anthropic import ChatAnthropic
from llama_index.llms.langchain import LangChainLLM

from metis.providers.base import LLMProvider
from metis.providers.openai_embeddings import build_openai_compatible_embedding_model
from metis.providers.registry import register_provider


class AnthropicProvider(LLMProvider):
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.api_key = config.get("llm_api_key")
        self.embedding_api_key = config.get("embedding_api_key")
        self.query_model = config.get("llama_query_model") or config.get("model")
        self.temperature = config.get("llama_query_temperature", 0.0)
        self.max_tokens = int(config.get("llama_query_max_tokens", 512))
        self.base_url = config.get("anthropic_api_url") or config.get("base_url")

        self.code_embedding_model = config.get("code_embedding_model")
        self.docs_embedding_model = config.get("docs_embedding_model")
        self.code_embedding_extra_kwargs = config.get("code_embedding_extra_kwargs", {})
        self.docs_embedding_extra_kwargs = config.get("docs_embedding_extra_kwargs", {})
        self.embedding_api_base = config.get("embedding_api_base") or config.get(
            "embedding_base_url"
        )
        self.embedding_default_headers = config.get("embedding_default_headers", {})

        if not self.api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable is required for Anthropic provider but not set."
            )
        if not self.embedding_api_key:
            raise ValueError(
                "OPENAI_API_KEY environment variable is required for Anthropic provider embeddings but not set."
            )

    def get_embed_model_code(self, *, callback_manager=None):
        return build_openai_compatible_embedding_model(
            self.code_embedding_model,
            self.code_embedding_extra_kwargs,
            "code_embedding_model",
            api_key=self.embedding_api_key,
            api_base=self.embedding_api_base,
            default_headers=self.embedding_default_headers,
            callback_manager=callback_manager,
        )

    def get_embed_model_docs(self, *, callback_manager=None):
        return build_openai_compatible_embedding_model(
            self.docs_embedding_model,
            self.docs_embedding_extra_kwargs,
            "docs_embedding_model",
            api_key=self.embedding_api_key,
            api_base=self.embedding_api_base,
            default_headers=self.embedding_default_headers,
            callback_manager=callback_manager,
        )

    def get_query_engine_class(self):
        return LangChainLLM

    def get_query_model_kwargs(self, *, callback_manager=None, callbacks=None):
        params: dict[str, Any] = {"llm": self.get_chat_model(callbacks=callbacks)}
        if callback_manager is not None:
            params["callback_manager"] = callback_manager
        return params

    def get_chat_model(self, *args: Any, callbacks=None, **kwargs: Any):
        requested_model = kwargs.pop("model", None)
        positional_model = args[0] if args else None
        model_name = requested_model or positional_model or self.query_model
        if not model_name:
            raise ValueError("Missing chat model configuration")

        params: dict[str, Any] = {
            "model": model_name,
            "api_key": self.api_key,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }
        if "top_p" in kwargs and "temperature" in kwargs:
            raise ValueError(
                "Anthropic chat model accepts either temperature or top_p, not both."
            )
        if "top_p" not in kwargs:
            params["temperature"] = kwargs.get("temperature", self.temperature)
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

        return ChatAnthropic(**params)


register_provider("anthropic", AnthropicProvider)
