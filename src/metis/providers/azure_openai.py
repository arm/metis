# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging

from llama_index.embeddings.azure_openai import AzureOpenAIEmbedding
from llama_index.llms.azure_openai import AzureOpenAI as LlamaAzureOpenAI
from langchain_openai import AzureChatOpenAI

from metis.providers.base import LLMProvider
from metis.providers.registry import register_provider

logger = logging.getLogger(__name__)


class AzureOpenAIProvider(LLMProvider):

    def __init__(self, config):
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
        self.max_tokens = int(config.get("llama_query_max_tokens", 512))

        self.model_token_param = config.get(
            "model_token_param", "max_completion_tokens"
        )
        self.supports_temperature = config.get("supports_temperature", False)

    def get_embed_model_code(self):
        return AzureOpenAIEmbedding(
            model=self.code_embedding_model,
            deployment_name=self.code_embedding_deployment,
            api_key=self.api_key,
            azure_endpoint=self.azure_endpoint,
            api_version=self.api_version,
        )

    def get_embed_model_docs(self):
        return AzureOpenAIEmbedding(
            model=self.docs_embedding_model,
            deployment_name=self.docs_embedding_deployment,
            api_key=self.api_key,
            azure_endpoint=self.azure_endpoint,
            api_version=self.api_version,
        )

    def get_query_engine_class(self):
        return LlamaAzureOpenAI

    def get_query_model_kwargs(self):
        deployment = self.engine
        chat_model = self.chat_deployment_model
        params = {
            "model": chat_model,
            "engine": deployment,
            "api_key": self.api_key,
            "azure_endpoint": self.azure_endpoint,
            "api_version": self.api_version,
        }
        if self.supports_temperature:
            params["temperature"] = self.temperature
        return params

    def get_chat_model(self, deployment_name=None, **kwargs):
        deployment = deployment_name or self.engine
        params = {
            "api_key": self.api_key,
            "azure_endpoint": self.azure_endpoint,
            "api_version": self.api_version,
            "azure_deployment": deployment,
            "model": self.chat_deployment_model,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }
        if "response_format" in kwargs:
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
        return AzureChatOpenAI(**params)


register_provider("azure_openai", AzureOpenAIProvider)
