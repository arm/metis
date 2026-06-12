# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, cast

from langchain_core.callbacks import Callbacks

from metis.providers.base import ChatProvider
from metis.providers.config import ApiKeySources
from metis.providers.config import ProviderConfigSpec


class AnthropicProvider(ChatProvider):
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="Anthropic",
        required_keys=("model",),
        api_key=ApiKeySources(required=True, env_vars=("ANTHROPIC_API_KEY",)),
        copy_keys=("base_url", "model", "supports_temperature"),
    )

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.api_key = config.get("api_key")
        self.default_model = config.get("model")
        self.supports_temperature = bool(config.get("supports_temperature", False))
        self.base_url = config.get("base_url")

        if not self.api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable is required for Anthropic provider but not set."
            )

    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: object,
    ) -> Any:
        try:
            from langchain_anthropic import ChatAnthropic
        except ModuleNotFoundError as exc:
            raise ModuleNotFoundError(
                "Anthropic provider requires the langchain-anthropic extra."
            ) from exc

        requested_model = kwargs.pop("model", None)
        positional_model = args[0] if args else None
        model_name = requested_model or positional_model or self.default_model
        if not model_name:
            raise ValueError("Missing chat model configuration")

        params: dict[str, Any] = {
            "model": model_name,
            "api_key": self.api_key,
        }
        max_tokens = kwargs.get("max_tokens")
        if max_tokens is not None:
            params["max_tokens"] = int(max_tokens)
        if "top_p" in kwargs and "temperature" in kwargs:
            raise ValueError(
                "Anthropic chat model accepts either temperature or top_p, not both."
            )
        if self.supports_temperature and "top_p" not in kwargs:
            temperature = kwargs.get("temperature")
            if temperature is not None:
                params["temperature"] = float(temperature)
        if self.base_url:
            params["base_url"] = self.base_url
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

        return ChatAnthropic(**cast(dict[str, Any], params))
