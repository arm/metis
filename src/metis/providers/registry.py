# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from importlib import import_module
from typing import Dict, Type

from metis.providers.base import LLMProvider

_PROVIDERS: Dict[str, Type[LLMProvider]] = {}
_LOADERS: Dict[str, str] = {}


def register_provider(name: str, provider_cls: Type[LLMProvider]) -> None:
    """Register an LLM provider under a case-insensitive name."""
    key = name.lower()
    _PROVIDERS[key] = provider_cls


def register_provider_loader(name: str, dotted_path: str) -> None:
    """
    Register a deferred loader for a provider. The dotted path should be
    formatted as ``"module.submodule:ClassName"``.
    """
    key = name.lower()
    _LOADERS[key] = dotted_path


def _load_provider_from_path(name: str, dotted_path: str) -> Type[LLMProvider]:
    module_path, class_name = dotted_path.split(":", 1)
    module = import_module(module_path)

    # Provider modules can self-register on import.
    key = name.lower()
    if key in _PROVIDERS:
        return _PROVIDERS[key]

    provider_cls = getattr(module, class_name)
    register_provider(name, provider_cls)
    return provider_cls


def get_provider(name: str) -> Type[LLMProvider]:
    """Fetch a previously registered provider class."""
    key = name.lower()
    if key in _PROVIDERS:
        return _PROVIDERS[key]

    dotted_path = _LOADERS.get(key)
    if dotted_path:
        try:
            return _load_provider_from_path(name, dotted_path)
        except ModuleNotFoundError as exc:
            raise ModuleNotFoundError(
                f"Provider '{name}' is registered but required dependencies are missing."
            ) from exc

    raise ValueError(f"Unsupported LLM provider: {name}")


def registered_providers() -> Dict[str, Type[LLMProvider]]:
    """Return a copy of the provider registry."""
    return dict(_PROVIDERS)


# Built-in provider loaders (lazy import until requested)
register_provider_loader("openai", "metis.providers.openai:OpenAIProvider")
register_provider_loader(
    "azure_openai", "metis.providers.azure_openai:AzureOpenAIProvider"
)
register_provider_loader("vllm", "metis.providers.vllm:VLLMProvider")
register_provider_loader("ollama", "metis.providers.ollama:OllamaProvider")
