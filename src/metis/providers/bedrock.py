# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Mapping, cast
from typing import Required, TypedDict

from langchain_core.callbacks import Callbacks
from llama_index.core.callbacks import CallbackManager

from metis.providers.base import ChatProvider
from metis.providers.base import EmbeddingProvider
from metis.providers.embedding_adapter import LangChainEmbeddingAdapter
from metis.providers.config import ProviderConfigSpec


AWS_CREDENTIAL_CONFIG = {
    "endpoint_url": ("endpoint_url",),
    "aws_profile": ("aws_profile",),
    "aws_access_key_id": ("aws_access_key_id", "env:AWS_ACCESS_KEY_ID"),
    "aws_secret_access_key": ("aws_secret_access_key", "env:AWS_SECRET_ACCESS_KEY"),
    "aws_session_token": ("aws_session_token", "env:AWS_SESSION_TOKEN"),
}

BedrockEmbeddings: Any
ChatBedrockConverse: Any

try:
    from langchain_aws import BedrockEmbeddings
    from langchain_aws import ChatBedrockConverse
except ModuleNotFoundError:
    BedrockEmbeddings = None
    ChatBedrockConverse = None


class BedrockChatConfig(TypedDict, total=False):
    region: Required[str]
    model: Required[str]
    supports_temperature: bool
    aws_profile: str
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_session_token: str
    endpoint_url: str


class BedrockEmbeddingConfig(TypedDict, total=False):
    region: Required[str]
    code_embedding_model: Required[str]
    docs_embedding_model: Required[str]
    aws_profile: str
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_session_token: str
    endpoint_url: str


def _credential_kwargs(config: Mapping[str, object]) -> dict[str, object]:
    region = config.get("region")
    if not region:
        raise ValueError("Bedrock provider requires 'region' in metis.yaml.")

    kwargs: dict[str, object] = {"region_name": region}
    endpoint_url = config.get("endpoint_url")
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    aws_profile = config.get("aws_profile")
    if aws_profile:
        kwargs["credentials_profile_name"] = aws_profile

    aws_access_key_id = config.get("aws_access_key_id")
    aws_secret_access_key = config.get("aws_secret_access_key")
    if aws_access_key_id and aws_secret_access_key:
        kwargs["aws_access_key_id"] = aws_access_key_id
        kwargs["aws_secret_access_key"] = aws_secret_access_key
        aws_session_token = config.get("aws_session_token")
        if aws_session_token:
            kwargs["aws_session_token"] = aws_session_token

    return kwargs


class BedrockProvider(ChatProvider):
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="AWS Bedrock",
        required_keys=("model", "region"),
        copy_keys={
            "model": ("model",),
            "region": ("region",),
            **AWS_CREDENTIAL_CONFIG,
            "supports_temperature": ("supports_temperature",),
        },
    )

    def __init__(self, config: BedrockChatConfig) -> None:
        self.config = config
        self.default_model = config.get("model")
        self.supports_temperature = bool(config.get("supports_temperature", False))
        self._credentials = _credential_kwargs(config)

    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: object,
    ) -> Any:
        if ChatBedrockConverse is None:
            raise ModuleNotFoundError(
                "AWS Bedrock provider requires the langchain-aws extra."
            )
        requested_model = kwargs.pop("model", None)
        positional_model = args[0] if args else None
        model_name = requested_model or positional_model or self.default_model
        if not model_name:
            raise ValueError("Missing chat model configuration")

        params: dict[str, object] = {
            "model": model_name,
            **self._credentials,
        }
        max_tokens = kwargs.get("max_tokens")
        if max_tokens is not None:
            params["max_tokens"] = int(max_tokens)
        if self.supports_temperature:
            temperature = kwargs.get("temperature")
            if temperature is not None:
                params["temperature"] = float(temperature)
        if callbacks is not None:
            params["callbacks"] = callbacks

        for optional_key in (
            "timeout",
            "request_timeout",
            "max_retries",
            "top_p",
            "stop",
        ):
            if optional_key in kwargs:
                params[optional_key] = kwargs[optional_key]

        return ChatBedrockConverse(**cast(dict[str, Any], params))


class BedrockEmbeddingProvider(EmbeddingProvider):
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="AWS Bedrock embeddings",
        required_keys=("region", "code_embedding_model", "docs_embedding_model"),
        copy_keys={
            "region": ("region",),
            **AWS_CREDENTIAL_CONFIG,
            "code_embedding_model": ("code_embedding_model",),
            "docs_embedding_model": ("docs_embedding_model",),
        },
    )

    def __init__(self, config: BedrockEmbeddingConfig) -> None:
        self.config = config
        self.code_embedding_model = config.get("code_embedding_model")
        self.docs_embedding_model = config.get("docs_embedding_model")
        self._credentials = _credential_kwargs(config)

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
            callback_manager=callback_manager,
        )

    def get_embed_model_docs(
        self, *, callback_manager: CallbackManager | None = None
    ) -> LangChainEmbeddingAdapter:
        return self._build_embedding_model(
            self.docs_embedding_model,
            callback_manager=callback_manager,
        )

    def _build_embedding_model(
        self,
        model_name: str,
        callback_manager: CallbackManager | None = None,
    ) -> LangChainEmbeddingAdapter:
        if BedrockEmbeddings is None:
            raise ModuleNotFoundError(
                "AWS Bedrock embeddings require the langchain-aws extra."
            )
        credential_kwargs = cast(dict[str, Any], self._credentials)
        client = BedrockEmbeddings(
            model_id=model_name,
            **credential_kwargs,
        )
        return LangChainEmbeddingAdapter(
            client,
            model_name=model_name,
            callback_manager=callback_manager,
        )
