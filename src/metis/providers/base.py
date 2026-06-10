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
    top_p: float
    top_k: int
    timeout: float
    request_timeout: float
    max_retries: int
    frequency_penalty: float
    presence_penalty: float
    seed: int
    logit_bias: Mapping[str, int]
    response_format: Mapping[str, object] | None
    stop: str | list[str]
    safety_settings: object
    thinking_budget: int
    thinking_level: str
    include_thoughts: bool
    response_mime_type: str
    response_schema: object
    n: int


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
    code_embedding_model: str
    docs_embedding_model: str
    code_embedding_extra_kwargs: Mapping[str, object]
    docs_embedding_extra_kwargs: Mapping[str, object]


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


class GeminiProviderConfig(TypedDict, total=False):
    llm_api_key: Required[str]
    model: Required[str]
    llama_query_model: str
    llama_query_temperature: float
    llama_query_max_tokens: int
    llama_query_reasoning_effort: str
    code_embedding_model: Required[str]
    docs_embedding_model: Required[str]
    code_embedding_extra_kwargs: Mapping[str, object]
    docs_embedding_extra_kwargs: Mapping[str, object]
    gemini_api_base: str
    gemini_additional_headers: Mapping[str, str]
    gemini_project: str
    gemini_location: str
    gemini_vertexai: bool | None
    gemini_client_args: Mapping[str, object]


ProviderRuntimeConfig = (
    OpenAICompatibleProviderConfig | AzureOpenAIProviderConfig | GeminiProviderConfig
)


class EmbedModelKwargs(TypedDict, total=False):
    callback_manager: CallbackManager


class ProviderChatModelKwargs(TypedDict, total=False):
    callbacks: Callbacks


class RetrieverKwargs(ProviderChatModelKwargs, total=False):
    callback_manager: CallbackManager


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
