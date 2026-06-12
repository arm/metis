# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import TypedDict

from langchain_core.callbacks import Callbacks
from langchain_core.language_models.chat_models import BaseChatModel
from llama_index.core.base.embeddings.base import BaseEmbedding
from llama_index.core.callbacks import CallbackManager


class EmbedModelKwargs(TypedDict, total=False):
    callback_manager: CallbackManager


class ProviderChatModelKwargs(TypedDict, total=False):
    callbacks: Callbacks


class RetrieverKwargs(ProviderChatModelKwargs, total=False):
    callback_manager: CallbackManager


class ChatProvider(ABC):
    def __init__(self, config: Mapping[str, object]) -> None:
        pass

    @abstractmethod
    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: object,
    ) -> BaseChatModel:
        """Return a LangChain chat model instance."""
        pass


class EmbeddingProvider(ABC):
    def __init__(self, config: Mapping[str, object]) -> None:
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
