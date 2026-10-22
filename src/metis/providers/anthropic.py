# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from langchain_core.callbacks import Callbacks

from metis.providers.base import ChatProvider
from metis.providers.config import ApiKeySources
from metis.providers.config import ProviderConfigSpec
from metis.utils import anthropic_token_count


def claude_chat_model_kwargs(
    options: Mapping[str, Any],
    *,
    model: Any,
    callbacks: Any,
    max_retries: int,
    supports_temperature: bool,
    reject_sampling_conflict: bool,
    provider_name: str,
) -> dict[str, Any]:
    if not model:
        raise ValueError("Missing chat model configuration")
    params = {"model": model, "max_retries": max_retries}
    max_tokens = options.get("max_tokens")
    if max_tokens is not None:
        params["max_tokens"] = int(max_tokens)
    if reject_sampling_conflict and "top_p" in options and "temperature" in options:
        raise ValueError(
            f"{provider_name} chat model accepts either temperature or top_p, not both."
        )
    temperature = options.get("temperature")
    if supports_temperature and temperature is not None:
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
        if optional_key in options:
            params[optional_key] = options[optional_key]
    return params


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
        self.max_retries = int(config.get("max_retries", 5))

        if not self.api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable is required for Anthropic provider but not set."
            )

    def count_tokens(self, text: str, model: str | None = None) -> int:
        return anthropic_token_count(text)

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
        params = claude_chat_model_kwargs(
            kwargs,
            model=model_name,
            callbacks=callbacks,
            max_retries=self.max_retries,
            supports_temperature=self.supports_temperature,
            reject_sampling_conflict=True,
            provider_name="Anthropic",
        )
        params["api_key"] = self.api_key
        if self.base_url:
            params["base_url"] = self.base_url
        return ChatAnthropic(**cast(dict[str, Any], params))
