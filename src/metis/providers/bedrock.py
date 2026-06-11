# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
from typing import Any, Unpack

from langchain_aws import BedrockEmbeddings, ChatBedrockConverse
from langchain_core.callbacks import Callbacks
from llama_index.core.callbacks import CallbackManager

from metis.providers.base import BedrockProviderConfig, ChatModelOptions, LLMProvider
from metis.providers.embedding_adapter import LangChainEmbeddingAdapter
from metis.providers.registry import register_provider

logger = logging.getLogger(__name__)


class BedrockProvider(LLMProvider):
    def __init__(self, config: BedrockProviderConfig) -> None:
        self.config = config
        self.region = config.get("bedrock_region") or config.get("aws_region")
        self.query_model = config.get("llama_query_model") or config.get("model")
        self.supports_temperature = bool(config.get("supports_temperature", False))
        self.temperature = float(config.get("llama_query_temperature", 0.0))
        self.max_tokens = int(config.get("llama_query_max_tokens", 3072))

        self.aws_profile = config.get("aws_profile") or None
        self.aws_access_key_id = config.get("aws_access_key_id") or None
        self.aws_secret_access_key = config.get("aws_secret_access_key") or None
        self.aws_session_token = config.get("aws_session_token") or None
        self.endpoint_url = config.get("bedrock_endpoint_url") or None

        self.code_embedding_model = config.get("code_embedding_model")
        self.docs_embedding_model = config.get("docs_embedding_model")

        if not self.region:
            raise ValueError(
                "Bedrock provider requires 'region' "
                "(set llm_provider.region in metis.yaml)."
            )

    def _credential_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"region_name": self.region}
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url
        if self.aws_profile:
            kwargs["credentials_profile_name"] = self.aws_profile
        if self.aws_access_key_id and self.aws_secret_access_key:
            kwargs["aws_access_key_id"] = self.aws_access_key_id
            kwargs["aws_secret_access_key"] = self.aws_secret_access_key
            if self.aws_session_token:
                kwargs["aws_session_token"] = self.aws_session_token
        return kwargs

    def _build_embedding_model(
        self,
        model_id: str | None,
        config_key: str,
        callback_manager: CallbackManager | None = None,
    ) -> LangChainEmbeddingAdapter:
        if not model_id:
            raise ValueError(f"Missing '{config_key}' in configuration")
        client = BedrockEmbeddings(model_id=model_id, **self._credential_kwargs())
        return LangChainEmbeddingAdapter(
            client,
            model_name=model_id,
            callback_manager=callback_manager,
        )

    def get_embed_model_code(
        self, *, callback_manager: CallbackManager | None = None
    ) -> LangChainEmbeddingAdapter:
        return self._build_embedding_model(
            self.code_embedding_model,
            "code_embedding_model",
            callback_manager=callback_manager,
        )

    def get_embed_model_docs(
        self, *, callback_manager: CallbackManager | None = None
    ) -> LangChainEmbeddingAdapter:
        return self._build_embedding_model(
            self.docs_embedding_model,
            "docs_embedding_model",
            callback_manager=callback_manager,
        )

    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: Unpack[ChatModelOptions],
    ) -> ChatBedrockConverse:
        requested_model = kwargs.pop("model", None)
        positional_model = args[0] if args else None
        model_id = requested_model or positional_model or self.query_model
        if not model_id:
            raise ValueError("Missing chat model configuration")

        params: dict[str, Any] = {
            "model": model_id,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            **self._credential_kwargs(),
        }
        if "temperature" in kwargs:
            params["temperature"] = kwargs["temperature"]
        elif self.supports_temperature:
            params["temperature"] = self.temperature
        if callbacks is not None:
            params["callbacks"] = callbacks

        for optional_key in ("top_p", "stop", "max_retries"):
            if optional_key in kwargs:
                params[optional_key] = kwargs[optional_key]

        return ChatBedrockConverse(**params)


register_provider("bedrock", BedrockProvider)
