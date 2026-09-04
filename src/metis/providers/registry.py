# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from typing import Literal, Type, TypeVar

from metis.providers.base import ChatProvider
from metis.providers.base import EmbeddingProvider

_PROVIDER_ENTRY_POINT_GROUP = "metis.providers"
_PROVIDER_ENTRY_POINT_SURFACES = {"chat", "embedding"}
_CHAT_PROVIDERS: dict[str, Type[ChatProvider]] = {}
_EMBEDDING_PROVIDERS: dict[str, Type[EmbeddingProvider]] = {}
_PROVIDER_LOADERS_DISCOVERED = False

ProviderT = TypeVar("ProviderT", ChatProvider, EmbeddingProvider)
ProviderSurface = Literal["chat", "embedding"]


@dataclass(frozen=True)
class ProviderLoader:
    chat: str | None = None
    embedding: str | None = None


_PROVIDER_LOADERS: dict[str, ProviderLoader] = {}


def _register_provider_loader(
    name: str, *, chat: str | None = None, embedding: str | None = None
) -> None:
    if chat is None and embedding is None:
        raise ValueError("Provider loader must define a chat or embedding class.")
    key = name.lower()
    current = _PROVIDER_LOADERS.get(key, ProviderLoader())
    if chat is not None and current.chat not in (None, chat):
        raise ValueError(f"Chat provider loader already registered for: {name}")
    if embedding is not None and current.embedding not in (None, embedding):
        raise ValueError(f"Embedding provider loader already registered for: {name}")
    _PROVIDER_LOADERS[key] = ProviderLoader(
        chat=chat or current.chat,
        embedding=embedding or current.embedding,
    )


def get_chat_provider(name: str) -> Type[ChatProvider]:
    return _get_provider(name, "chat", _CHAT_PROVIDERS)


def get_embedding_provider(name: str) -> Type[EmbeddingProvider]:
    return _get_provider(name, "embedding", _EMBEDDING_PROVIDERS)


def _get_provider(
    name: str,
    surface: ProviderSurface,
    providers: dict[str, Type[ProviderT]],
) -> Type[ProviderT]:
    key = name.lower()
    if provider_cls := providers.get(key):
        return provider_cls
    _discover_provider_loaders()
    loader = _PROVIDER_LOADERS.get(key)
    dotted_path = getattr(loader, surface) if loader else None
    if not dotted_path:
        raise ValueError(f"Unsupported {surface} provider: {name}")

    try:
        provider_cls = metadata.EntryPoint(
            name=f"{name}.{surface}",
            value=dotted_path,
            group=_PROVIDER_ENTRY_POINT_GROUP,
        ).load()
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            f"{surface.capitalize()} provider '{name}' is registered but required "
            "dependencies are missing."
        ) from exc
    providers[key] = provider_cls
    return provider_cls


def _discover_provider_loaders() -> None:
    global _PROVIDER_LOADERS_DISCOVERED
    if _PROVIDER_LOADERS_DISCOVERED:
        return

    for entry_point in metadata.entry_points().select(
        group=_PROVIDER_ENTRY_POINT_GROUP
    ):
        provider_name, surface = _parse_provider_entry_point_name(entry_point.name)
        if surface == "chat":
            _register_provider_loader(provider_name, chat=entry_point.value)
        else:
            _register_provider_loader(provider_name, embedding=entry_point.value)

    _PROVIDER_LOADERS_DISCOVERED = True


def _parse_provider_entry_point_name(name: str) -> tuple[str, str]:
    provider_name, separator, surface = name.rpartition(".")
    if (
        not separator
        or not provider_name
        or surface not in _PROVIDER_ENTRY_POINT_SURFACES
    ):
        surfaces = ", ".join(sorted(_PROVIDER_ENTRY_POINT_SURFACES))
        raise ValueError(
            f"Provider entry point '{name}' must be named '<provider>.<{surfaces}>'."
        )
    return provider_name, surface
