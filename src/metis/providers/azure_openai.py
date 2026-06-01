# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Unpack, cast

import logging
from langchain_openai import AzureChatOpenAI, AzureOpenAIEmbeddings
from langchain_core.callbacks import Callbacks
from pydantic import SecretStr
from llama_index.core.base.embeddings.base import BaseEmbedding, Embedding
from llama_index.core.callbacks import CallbackManager
from llama_index.llms.langchain import LangChainLLM

from metis.providers.base import (
    AzureOpenAIProviderConfig,
    ChatModelOptions,
    LLMProvider,
    QueryModelKwargs,
)
from metis.providers.registry import register_provider

logger = logging.getLogger(__name__)


class AzureOpenAIEmbeddingAdapter(BaseEmbedding):
    """Use LangChain's Azure embeddings client behind LlamaIndex's interface."""

    _client: AzureOpenAIEmbeddings

    def __init__(
        self,
        client: AzureOpenAIEmbeddings,
        callback_manager: CallbackManager | None = None,
    ) -> None:
        if callback_manager is None:
            super().__init__(model_name=client.model)
        else:
            super().__init__(model_name=client.model, callback_manager=callback_manager)
        self._client = client

    def _get_query_embedding(self, query: str) -> Embedding:
        return self._client.embed_query(query)

    async def _aget_query_embedding(self, query: str) -> Embedding:
        return await self._client.aembed_query(query)

    def _get_text_embedding(self, text: str) -> Embedding:
        return self._client.embed_query(text)

    async def _aget_text_embedding(self, text: str) -> Embedding:
        return await self._client.aembed_query(text)

    def _get_text_embeddings(self, texts: list[str]) -> list[Embedding]:
        return self._client.embed_documents(texts)

    async def _aget_text_embeddings(self, texts: list[str]) -> list[Embedding]:
        return await self._client.aembed_documents(texts)


class AzureOpenAIProvider(LLMProvider):
    def __init__(self, config: AzureOpenAIProviderConfig) -> None:
        self.api_key = config["llm_api_key"]
        self.azure_endpoint = config["azure_endpoint"]
        self.api_version = config["azure_api_version"]
        self.engine = config["engine"]
        self.chat_deployment_model = config["chat_deployment_model"]

        if not self.engine:
            raise ValueError("Missing 'engine' (Azure deployment name).")

        if not self.chat_deployment_model:
            raise ValueError(
                "Missing 'chat_deployment_model' "
                "Azure calls must specify a deployment model."
            )

        self.code_embedding_model = config["code_embedding_model"]
        self.docs_embedding_model = config["docs_embedding_model"]
        self.code_embedding_deployment = config.get(
            "code_embedding_deployment", self.code_embedding_model
        )
        self.docs_embedding_deployment = config.get(
            "docs_embedding_deployment", self.docs_embedding_model
        )

        self.temperature = float(config.get("llama_query_temperature", 0.0))
        self.max_tokens = int(config.get("llama_query_max_tokens", 3072))
        self.reasoning_effort = config.get("llama_query_reasoning_effort")

        self.model_token_param = config.get(
            "model_token_param", "max_completion_tokens"
        )
        self.supports_temperature = config.get("supports_temperature", False)

    def get_embed_model_code(
        self, *, callback_manager: CallbackManager | None = None
    ) -> AzureOpenAIEmbeddingAdapter:
        return AzureOpenAIEmbeddingAdapter(
            self._build_embeddings_client(
                model=self.code_embedding_model,
                deployment=self.code_embedding_deployment,
            ),
            callback_manager=callback_manager,
        )

    def get_embed_model_docs(
        self, *, callback_manager: CallbackManager | None = None
    ) -> AzureOpenAIEmbeddingAdapter:
        return AzureOpenAIEmbeddingAdapter(
            self._build_embeddings_client(
                model=self.docs_embedding_model,
                deployment=self.docs_embedding_deployment,
            ),
            callback_manager=callback_manager,
        )

    def get_query_engine_class(self) -> type[LangChainLLM]:
        return LangChainLLM

    def get_query_model_kwargs(
        self,
        *,
        callback_manager: CallbackManager | None = None,
        callbacks: Callbacks = None,
    ) -> QueryModelKwargs:
        params: dict[str, object] = {
            "llm": self.get_chat_model(
                response_format=None,
                callbacks=callbacks,
            )
        }
        if callback_manager is not None:
            params["callback_manager"] = callback_manager
        return params

    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: Unpack[ChatModelOptions],
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
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "use_responses_api": True,
        }
        if callbacks is not None:
            params["callbacks"] = callbacks
        if self.reasoning_effort:
            params["reasoning_effort"] = self.reasoning_effort
        if "response_format" in kwargs:
            if kwargs["response_format"] is not None:
                params["response_format"] = kwargs["response_format"]
        else:
            params["response_format"] = {"type": "json_object"}
        if self.supports_temperature:
            params["temperature"] = kwargs.get("temperature", self.temperature)
        for optional_key in (
            "timeout",
            "max_retries",
            "seed",
            "frequency_penalty",
            "presence_penalty",
            "response_format",
        ):
            if optional_key in kwargs and optional_key != "response_format":
                params[optional_key] = kwargs[optional_key]
        return AzureChatOpenAI(**cast(dict[str, Any], params))

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


register_provider("azure_openai", AzureOpenAIProvider)
