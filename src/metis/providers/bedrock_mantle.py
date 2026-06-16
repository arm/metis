# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from functools import cached_property
from typing import Any, cast

from langchain_core.callbacks import Callbacks
from pydantic import Field

from metis.providers.base import ChatProvider
from metis.providers.config import ProviderConfigSpec

AnthropicBedrockMantle: Any
AsyncAnthropicBedrockMantle: Any
ChatAnthropic: Any
ChatBedrockMantle: Any

try:
    from anthropic import AnthropicBedrockMantle
    from anthropic import AsyncAnthropicBedrockMantle
    from langchain_anthropic import ChatAnthropic
except ModuleNotFoundError:
    AnthropicBedrockMantle = None
    AsyncAnthropicBedrockMantle = None
    ChatAnthropic = None


if ChatAnthropic is not None:

    class ChatBedrockMantle(ChatAnthropic):
        """Anthropic chat model transported through Amazon Bedrock Mantle."""

        aws_region: str | None = None
        aws_profile: str | None = None
        bedrock_base_url: str | None = Field(default=None, alias="bedrock_base_url")

        @property
        def _llm_type(self) -> str:
            return "anthropic-bedrock-mantle-chat"

        def _bedrock_client_params(self) -> dict[str, Any]:
            params: dict[str, Any] = {
                "aws_region": self.aws_region,
                "aws_profile": self.aws_profile,
                "max_retries": self.max_retries,
            }
            if self.bedrock_base_url:
                params["base_url"] = self.bedrock_base_url
            if self.default_headers:
                params["default_headers"] = self.default_headers
            if self.default_request_timeout is None or self.default_request_timeout > 0:
                params["timeout"] = self.default_request_timeout
            return {key: value for key, value in params.items() if value is not None}

        @cached_property
        def _client(self) -> AnthropicBedrockMantle:
            return AnthropicBedrockMantle(**self._bedrock_client_params())

        @cached_property
        def _async_client(self) -> AsyncAnthropicBedrockMantle:
            return AsyncAnthropicBedrockMantle(**self._bedrock_client_params())

else:
    ChatBedrockMantle = None


class BedrockMantleProvider(ChatProvider):
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="Bedrock Mantle",
        required_keys=("model",),
        copy_keys=(
            "model",
            "aws_profile",
            "aws_region",
            "base_url",
            "default_headers",
            "supports_temperature",
        ),
    )

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.default_model = config.get("model")
        self.supports_temperature = bool(config.get("supports_temperature", False))
        self.aws_region = config.get("aws_region")
        self.aws_profile = config.get("aws_profile")
        self.base_url = config.get("base_url")
        self.default_headers = dict(config.get("default_headers", {}))
        self.max_retries = int(config.get("max_retries", 5))

    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: object,
    ) -> Any:
        if ChatBedrockMantle is None:
            raise ModuleNotFoundError(
                "Bedrock Mantle provider requires the anthropic and "
                "langchain-anthropic extras."
            )
        requested_model = kwargs.pop("model", None)
        positional_model = args[0] if args else None
        model_name = requested_model or positional_model or self.default_model
        if not model_name:
            raise ValueError("Missing chat model configuration")

        params: dict[str, Any] = {
            "model": model_name,
            "aws_region": self.aws_region,
            "aws_profile": self.aws_profile,
            "max_retries": self.max_retries,
        }
        max_tokens = kwargs.get("max_tokens")
        if max_tokens is not None:
            params["max_tokens"] = int(max_tokens)
        if self.base_url:
            params["bedrock_base_url"] = self.base_url
        if self.default_headers:
            params["default_headers"] = self.default_headers
        if self.supports_temperature:
            if "top_p" in kwargs and "temperature" in kwargs:
                raise ValueError(
                    "Bedrock Mantle chat model accepts either temperature or top_p, not both."
                )
            if "temperature" in kwargs:
                temperature = kwargs["temperature"]
            elif "top_p" not in kwargs:
                temperature = None
            else:
                temperature = None
            if temperature is not None:
                params["temperature"] = float(temperature)
        if callbacks is not None:
            params["callbacks"] = callbacks

        for optional_key in (
            "timeout",
            "default_request_timeout",
            "max_retries",
            "top_k",
            "top_p",
            "stop_sequences",
        ):
            if optional_key in kwargs:
                params[optional_key] = kwargs[optional_key]

        return ChatBedrockMantle(**cast(dict[str, Any], params))
