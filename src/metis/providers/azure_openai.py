# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging

from llama_index.embeddings.azure_openai import AzureOpenAIEmbedding
from openai import AzureOpenAI

from metis.providers.base import LLMProvider

logger = logging.getLogger(__name__)


class AzureOpenAIProvider(LLMProvider):

    def __init__(self, config: dict):
        self.api_key = config["llm_api_key"]
        self.azure_endpoint = config["azure_endpoint"]
        self.api_version = config["azure_api_version"]
        self.chat_deployment_name = config["chat_deployment_name"]

        if not self.chat_deployment_name:
            raise ValueError(
                "Missing 'chat_deployment_name' "
                "Azure calls must specify a deployment name."
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

    def get_query_engine_class(self):
        return AzureOpenAI

    def get_query_model_kwargs(self):
        return {
            "deployment_name": self.chat_deployment_name,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

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

    def get_llm_client(self):
        return AzureOpenAI(
            api_key=self.api_key,
            azure_endpoint=self.azure_endpoint,
            api_version=self.api_version,
        )

    def call_llm(self, system_prompt, prompt, deployment_name=None, **kwargs):
        client = self.get_llm_client()
        deployment = deployment_name or self.chat_deployment_name

        try:
            response = client.chat.completions.create(
                model=deployment,
                messages=[
                    {"role": "system", "content": system_prompt or ""},
                    {"role": "user", "content": prompt or ""},
                ],
                temperature=kwargs.get("temperature", self.temperature),
                max_tokens=kwargs.get("max_tokens", self.max_tokens),
            )
            return (response.choices[0].message.content or "").strip()
        except Exception as e:
            logger.exception("Error calling Azure OpenAI API: %s", e)
            return ""
