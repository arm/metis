# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Required, TypedDict, cast

from langchain_core.callbacks import Callbacks

from metis.providers.base import ChatProvider
from metis.providers.config import ApiKeySources
from metis.providers.config import ProviderConfigSpec


class GeminiChatConfig(TypedDict, total=False):
    api_key: str
    model: Required[str]
    base_url: str
    additional_headers: Mapping[str, str]
    project: str
    location: str
    vertexai: bool | None
    client_args: Mapping[str, object]
    max_retries: int


class GeminiProvider(ChatProvider):
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="Gemini",
        required_keys=("model",),
        api_key=ApiKeySources(
            required=True,
            env_vars=("GOOGLE_API_KEY", "GEMINI_API_KEY"),
            optional_when=("vertexai", True),
        ),
        copy_keys=(
            "model",
            "base_url",
            "additional_headers",
            "project",
            "location",
            "vertexai",
            "client_args",
        ),
    )

    def __init__(self, config: GeminiChatConfig) -> None:
        self.config = config
        self.api_key = config.get("api_key")
        self.default_model = config.get("model")
        self.base_url = config.get("base_url")
        self.additional_headers = dict(config.get("additional_headers", {}))
        self.project = config.get("project")
        self.location = config.get("location")
        self.vertexai = config.get("vertexai")
        self.client_args = dict(config.get("client_args", {}))
        self.max_retries = int(config.get("max_retries", 5))

        if not self.api_key and not self.vertexai:
            raise ValueError(
                "GOOGLE_API_KEY or GEMINI_API_KEY environment variable is required "
                "for Gemini provider but not set."
            )
        if not self.default_model:
            raise ValueError("Missing chat model configuration (set 'model')")

    def _common_params(self) -> dict[str, object]:
        params: dict[str, object] = {}
        if self.api_key:
            params["api_key"] = self.api_key
        if self.base_url:
            params["base_url"] = self.base_url
        if self.additional_headers:
            params["additional_headers"] = self.additional_headers
        if self.project:
            params["project"] = self.project
        if self.location:
            params["location"] = self.location
        if self.vertexai is not None:
            params["vertexai"] = self.vertexai
        if self.client_args:
            params["client_args"] = self.client_args
        return params

    def get_chat_model(
        self,
        *args: str,
        callbacks: Callbacks = None,
        **kwargs: object,
    ) -> Any:
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
        except ModuleNotFoundError as exc:
            raise ModuleNotFoundError(
                "Gemini provider requires the langchain-google-genai extra."
            ) from exc

        requested_model = kwargs.pop("model", None)
        positional_model = args[0] if args else None
        model_name = requested_model or positional_model or self.default_model
        if not model_name:
            raise ValueError("Missing chat model configuration")

        response_format = kwargs.pop("response_format", None)
        params: dict[str, object] = {
            "model": model_name,
            "max_retries": self.max_retries,
            **self._common_params(),
        }
        temperature = kwargs.get("temperature")
        if temperature is not None:
            params["temperature"] = float(temperature)
        max_tokens = kwargs.get("max_tokens")
        if max_tokens is not None:
            params["max_tokens"] = int(max_tokens)
        if callbacks is not None:
            params["callbacks"] = callbacks

        if (
            isinstance(response_format, Mapping)
            and response_format.get("type") == "json_object"
            and "response_mime_type" not in kwargs
        ):
            params["response_mime_type"] = "application/json"

        reasoning_effort = kwargs.get("reasoning_effort")
        if (
            "thinking_level" not in kwargs
            and isinstance(reasoning_effort, str)
            and reasoning_effort in {"minimal", "low", "medium", "high"}
        ):
            params["thinking_level"] = reasoning_effort

        for optional_key in (
            "timeout",
            "max_retries",
            "top_p",
            "top_k",
            "stop",
            "n",
            "safety_settings",
            "thinking_budget",
            "thinking_level",
            "include_thoughts",
            "response_mime_type",
            "response_schema",
            "seed",
        ):
            if optional_key in kwargs:
                params[optional_key] = kwargs[optional_key]

        chat_model = ChatGoogleGenerativeAI(**cast(dict[str, Any], params))
        if temperature is None:
            cast(Any, chat_model).temperature = None
        return chat_model
