# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, cast

from langchain_core.callbacks import Callbacks
from pydantic import model_validator

from metis.providers.anthropic import claude_chat_model_kwargs
from metis.providers.base import ChatProvider
from metis.providers.config import ProviderConfigSpec
from metis.utils import anthropic_token_count

ChatAnthropicMantle: Any
ChatBedrockMantle: Any

try:
    from langchain_aws import ChatAnthropicMantle
except ModuleNotFoundError:
    ChatAnthropicMantle = None


if ChatAnthropicMantle is not None:

    class ChatBedrockMantle(ChatAnthropicMantle):
        """LangChain Mantle model with Metis connection option names."""

        aws_region: str | None = None
        aws_profile: str | None = None
        bedrock_base_url: str | None = None

        @model_validator(mode="before")
        @classmethod
        def _resolve_gateway(cls, values: Any) -> Any:
            if not isinstance(values, dict):
                return values
            values = dict(values)
            values.setdefault("region_name", values.get("aws_region"))
            values.setdefault("credentials_profile_name", values.get("aws_profile"))
            values.setdefault("base_url", values.get("bedrock_base_url"))
            for key in (
                "bedrock_api_key",
                "aws_access_key_id",
                "aws_secret_access_key",
                "aws_session_token",
            ):
                values.setdefault(key, None)
            return values

        @property
        def _llm_type(self) -> str:
            return "anthropic-bedrock-mantle-chat"

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

    def count_tokens(self, text: str, model: str | None = None) -> int:
        return anthropic_token_count(text)

    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: object,
    ) -> Any:
        if ChatBedrockMantle is None:
            raise ModuleNotFoundError(
                "Bedrock Mantle provider requires the bedrock-mantle extra: "
                "pip install 'metis[bedrock-mantle]'"
            )
        requested_model = kwargs.pop("model", None)
        positional_model = args[0] if args else None
        model_name = requested_model or positional_model or self.default_model
        params = claude_chat_model_kwargs(
            kwargs,
            model=model_name,
            callbacks=callbacks,
            max_retries=self.max_retries,
            supports_temperature=self.supports_temperature,
            reject_sampling_conflict=self.supports_temperature,
            provider_name="Bedrock Mantle",
        )
        params["aws_region"] = self.aws_region
        params["aws_profile"] = self.aws_profile
        if self.base_url:
            params["bedrock_base_url"] = self.base_url
        if self.default_headers:
            params["default_headers"] = self.default_headers
        return ChatBedrockMantle(**cast(dict[str, Any], params))
