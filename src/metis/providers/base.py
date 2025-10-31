# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod


class LLMProvider(ABC):

    @abstractmethod
    def get_embed_model_code(self):
        """Return a code embedding model for vector store."""
        pass

    @abstractmethod
    def get_embed_model_docs(self):
        """Return a docs embedding model for vector store."""
        pass

    @abstractmethod
    def get_chat_model(self, **kwargs):
        """Return a LangChain chat model instance."""
        pass
