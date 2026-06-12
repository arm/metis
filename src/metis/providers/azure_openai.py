# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, NotRequired, Required, TypedDict, cast

from langchain_core.callbacks import Callbacks
from langchain_openai import AzureChatOpenAI
from langchain_openai import AzureOpenAIEmbeddings
from llama_index.core.callbacks import CallbackManager
from pydantic import SecretStr

from metis.providers.base import ChatProvider
from metis.providers.base import EmbeddingProvider
from metis.providers.embedding_adapter import LangChainEmbeddingAdapter
from metis.providers.config import ApiKeySources
from metis.providers.config import ProviderConfigSpec


class AzureOpenAIChatConfig(TypedDict, total=False):
    api_key: Required[str]
    azure_endpoint: Required[str]
    azure_api_version: Required[str]
    engine: Required[str]
    chat_deployment_model: Required[str]
    model: NotRequired[str]
    supports_temperature: NotRequired[bool]
    use_responses_api: NotRequired[bool]


class AzureOpenAIEmbeddingConfig(TypedDict, total=False):
    api_key: Required[str]
    azure_endpoint: Required[str]
    azure_api_version: Required[str]
    code_embedding_model: Required[str]
    docs_embedding_model: Required[str]
    code_deployment: Required[str]
    docs_deployment: Required[str]


class AzureOpenAIProvider(ChatProvider):
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="Azure OpenAI",
        required_keys=(
            "azure_endpoint",
            "azure_api_version",
            "engine",
            "chat_deployment_model",
        ),
        api_key=ApiKeySources(required=True, env_vars=("AZURE_OPENAI_API_KEY",)),
        copy_keys={
            "azure_endpoint": ("azure_endpoint",),
            "azure_api_version": ("azure_api_version",),
            "engine": ("engine",),
            "chat_deployment_model": ("chat_deployment_model",),
            "model": ("chat_deployment_model",),
            "supports_temperature": ("supports_temperature",),
            "use_responses_api": ("use_responses_api",),
        },
    )

    def __init__(self, config: AzureOpenAIChatConfig) -> None:
        self.api_key = config["api_key"]
        self.azure_endpoint = config["azure_endpoint"]
        self.api_version = config["azure_api_version"]
        self.engine = config["engine"]
        self.chat_deployment_model = config["chat_deployment_model"]
        self.supports_temperature = config.get("supports_temperature", False)
        self.use_responses_api = config.get("use_responses_api")

        if not self.engine:
            raise ValueError("Missing 'engine' (Azure deployment name).")
        if not self.chat_deployment_model:
            raise ValueError(
                "Missing 'chat_deployment_model' "
                "Azure calls must specify a deployment model."
            )

    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: object,
    ) -> AzureChatOpenAI:
        requested_deployment = kwargs.pop("deployment_name", None)
        positional_deployment = args[0] if args else None
        deployment = requested_deployment or positional_deployment or self.engine
        params: dict[str, object] = {
            "api_key": self.api_key,
            "azure_endpoint": self.azure_endpoint,
            "api_version": self.api_version,
            "azure_deployment": deployment,
            "model": self.chat_deployment_model,
        }
        if self.use_responses_api is not None:
            params["use_responses_api"] = bool(self.use_responses_api)
        max_tokens = kwargs.get("max_tokens")
        if max_tokens is not None:
            params["max_tokens"] = int(max_tokens)
        if callbacks is not None:
            params["callbacks"] = callbacks
        if "response_format" in kwargs:
            if kwargs["response_format"] is not None:
                params["response_format"] = kwargs["response_format"]
        else:
            params["response_format"] = {"type": "json_object"}
        if self.supports_temperature:
            temperature = kwargs.get("temperature")
            if temperature is not None:
                params["temperature"] = float(temperature)
        for optional_key in (
            "timeout",
            "max_retries",
            "seed",
            "frequency_penalty",
            "presence_penalty",
            "reasoning_effort",
            "verbosity",
        ):
            if optional_key in kwargs:
                params[optional_key] = kwargs[optional_key]
        return AzureChatOpenAI(**cast(dict[str, Any], params))


class AzureOpenAIEmbeddingProvider(EmbeddingProvider):
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="Azure OpenAI embeddings",
        required_keys=(
            "azure_endpoint",
            "azure_api_version",
            "code_embedding_model",
            "docs_embedding_model",
            "code_deployment",
            "docs_deployment",
        ),
        api_key=ApiKeySources(required=True, env_vars=("AZURE_OPENAI_API_KEY",)),
        copy_keys=(
            "azure_endpoint",
            "azure_api_version",
            "code_embedding_model",
            "docs_embedding_model",
            "code_deployment",
            "docs_deployment",
        ),
    )

    def __init__(self, config: AzureOpenAIEmbeddingConfig) -> None:
        self.api_key = config["api_key"]
        self.azure_endpoint = config["azure_endpoint"]
        self.api_version = config["azure_api_version"]
        self.code_embedding_model = config["code_embedding_model"]
        self.docs_embedding_model = config["docs_embedding_model"]
        self.code_deployment = config["code_deployment"]
        self.docs_deployment = config["docs_deployment"]

    def get_embed_model_code(
        self, *, callback_manager: CallbackManager | None = None
    ) -> LangChainEmbeddingAdapter:
        return LangChainEmbeddingAdapter(
            self._build_embeddings_client(
                model=self.code_embedding_model,
                deployment=self.code_deployment,
            ),
            model_name=self.code_embedding_model,
            callback_manager=callback_manager,
        )

    def get_embed_model_docs(
        self, *, callback_manager: CallbackManager | None = None
    ) -> LangChainEmbeddingAdapter:
        return LangChainEmbeddingAdapter(
            self._build_embeddings_client(
                model=self.docs_embedding_model,
                deployment=self.docs_deployment,
            ),
            model_name=self.docs_embedding_model,
            callback_manager=callback_manager,
        )

    def _build_embeddings_client(
        self, model: str, deployment: str
    ) -> AzureOpenAIEmbeddings:
        return AzureOpenAIEmbeddings(
            model=model,
            azure_deployment=deployment,
            api_key=SecretStr(self.api_key),
            azure_endpoint=self.azure_endpoint,
            api_version=self.api_version,
            base_url=None,
        )
