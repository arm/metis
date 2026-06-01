# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import NotRequired, Required, TypedDict, Unpack

from langchain_core.callbacks import Callbacks
from langchain_core.language_models.chat_models import BaseChatModel
from llama_index.core.base.embeddings.base import BaseEmbedding
from llama_index.core.callbacks import CallbackManager


class ChatModelOptions(TypedDict, total=False):
    model: str
    deployment_name: str
    temperature: float
    max_tokens: int
    timeout: float
    request_timeout: float
    max_retries: int
    frequency_penalty: float
    presence_penalty: float
    seed: int
    logit_bias: Mapping[str, int]
    response_format: Mapping[str, object] | None


class OpenAICompatibleProviderConfig(TypedDict, total=False):
    llm_api_key: str
    openai_api_base: str
    api_base: str
    base_url: str
    openai_default_headers: Mapping[str, str]
    default_headers: Mapping[str, str]
    model: str
    llama_query_model: str
    llama_query_temperature: float
    llama_query_max_tokens: int
    llama_query_reasoning_effort: str
    llama_query_context_window: int
    max_token_length: int
    code_embedding_model: str
    docs_embedding_model: str
    code_embedding_extra_kwargs: Mapping[str, object]
    docs_embedding_extra_kwargs: Mapping[str, object]
    force_openai_like: bool


class AzureOpenAIProviderConfig(TypedDict, total=False):
    llm_api_key: Required[str]
    azure_endpoint: Required[str]
    azure_api_version: Required[str]
    engine: Required[str]
    chat_deployment_model: Required[str]
    code_embedding_model: Required[str]
    docs_embedding_model: Required[str]
    code_embedding_deployment: NotRequired[str]
    docs_embedding_deployment: NotRequired[str]
    llama_query_temperature: NotRequired[float]
    llama_query_max_tokens: NotRequired[int]
    llama_query_reasoning_effort: NotRequired[str]
    model_token_param: NotRequired[str]
    supports_temperature: NotRequired[bool]


ProviderRuntimeConfig = OpenAICompatibleProviderConfig | AzureOpenAIProviderConfig


class EmbedModelKwargs(TypedDict, total=False):
    callback_manager: CallbackManager


class ProviderChatModelKwargs(TypedDict, total=False):
    callbacks: Callbacks


class QueryEngineKwargs(ProviderChatModelKwargs, total=False):
    callback_manager: CallbackManager


QueryModelKwargs = Mapping[str, object]


class LLMProvider(ABC):
    def __init__(self, config: ProviderRuntimeConfig) -> None:
        pass

    @abstractmethod
    def get_embed_model_code(
        self, *, callback_manager: CallbackManager | None = None
    ) -> BaseEmbedding:
        """Return a code embedding model for vector store."""
        pass

    @abstractmethod
    def get_embed_model_docs(
        self, *, callback_manager: CallbackManager | None = None
    ) -> BaseEmbedding:
        """Return a docs embedding model for vector store."""
        pass

    @abstractmethod
    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: Unpack[ChatModelOptions],
    ) -> BaseChatModel:
        """Return a LangChain chat model instance."""
        pass

    @abstractmethod
    def get_query_engine_class(self) -> type[object]:
        """Return the LlamaIndex LLM class used for query engines."""
        pass

    @abstractmethod
    def get_query_model_kwargs(
        self,
        *,
        callback_manager: CallbackManager | None = None,
        callbacks: Callbacks = None,
    ) -> QueryModelKwargs:
        """Return kwargs for constructing the query engine LLM."""
        pass
