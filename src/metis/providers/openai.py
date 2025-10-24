# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.embeddings.openai import OpenAIEmbedding
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

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

    def call_llm(self, system_prompt, prompt, model=None, **kwargs):
        model_name = model or self.query_model
        try:
            chat = ChatOpenAI(
                api_key=self.api_key,
                model=model_name,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )

            prompt_tmpl = ChatPromptTemplate.from_messages(
                [("system", "{system}"), ("user", "{input}")]
            )
            chain = prompt_tmpl | chat | StrOutputParser()
            return chain.invoke(
                {"system": system_prompt or "", "input": prompt or ""}
            ).strip()
        except Exception as e:
            logger.error(f"Error calling OpenAI via LangChain: {e}")
            return ""
