# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from typing import Any


class LLMProvider(ABC):

    @abstractmethod
    def get_embed_model_code(self, *, callback_manager=None):
        """Return a code embedding model for vector store."""
        pass

    @abstractmethod
    def get_embed_model_docs(self, *, callback_manager=None):
        """Return a docs embedding model for vector store."""
        pass

    @abstractmethod
    def get_chat_model(self, *args: Any, callbacks=None, **kwargs: Any):
        """Return a LangChain chat model instance."""
        pass

    @abstractmethod
    def get_query_engine_class(self):
        """Return the LlamaIndex LLM class used for query engines."""
        pass

    @abstractmethod
    def get_query_model_kwargs(self, *, callback_manager=None, callbacks=None):
        """Return kwargs for constructing the query engine LLM."""
        pass
