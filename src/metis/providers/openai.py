# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.llms.openai import OpenAI as LlamaOpenAI
from langchain_openai import ChatOpenAI

from metis.providers.base import LLMProvider

import logging

logger = logging.getLogger(__name__)


class OpenAIProvider(LLMProvider):
    def __init__(self, config):
        self.api_key = config["llm_api_key"]
        self.code_embedding_model = config["code_embedding_model"]
        self.docs_embedding_model = config["docs_embedding_model"]
        self.query_model = config["llama_query_model"]
        self.temperature = config.get("llama_query_temperature", 0.0)
        self.max_tokens = config.get("llama_query_max_tokens", 512)

    def get_embed_model_code(self):
        return OpenAIEmbedding(model_name=self.code_embedding_model)

    def get_embed_model_docs(self):
        return OpenAIEmbedding(model_name=self.docs_embedding_model)

    def get_query_engine_class(self):
        return LlamaOpenAI

    def get_query_model_kwargs(self):
        model_name = self.query_model
        params = {
            "model": model_name,
            "api_key": self.api_key,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        return params

    def get_chat_model(self, model=None, **kwargs):
        model_name = model or self.query_model
        params = {
            "api_key": self.api_key,
            "model": model_name,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }
        for optional_key in (
            "timeout",
            "max_retries",
            "frequency_penalty",
            "presence_penalty",
            "seed",
            "logit_bias",
        ):
            if optional_key in kwargs:
                params[optional_key] = kwargs[optional_key]
        return ChatOpenAI(**params)
