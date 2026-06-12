# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from importlib import import_module
from pathlib import Path
import tomllib
from typing import Type

from metis.providers.base import ChatProvider
from metis.providers.base import EmbeddingProvider

_PROVIDER_ENTRY_POINT_GROUP = "metis.providers"
_PROVIDER_ENTRY_POINT_SURFACES = {"chat", "embedding"}
_CHAT_PROVIDERS: dict[str, Type[ChatProvider]] = {}
_EMBEDDING_PROVIDERS: dict[str, Type[EmbeddingProvider]] = {}
_PROVIDER_LOADERS_DISCOVERED = False


@dataclass(frozen=True)
class ProviderLoader:
    chat: str | None = None
    embedding: str | None = None


_PROVIDER_LOADERS: dict[str, ProviderLoader] = {}


def _register_chat_provider(name: str, provider_cls: Type[ChatProvider]) -> None:
    _CHAT_PROVIDERS[name.lower()] = provider_cls


def _register_embedding_provider(
    name: str, provider_cls: Type[EmbeddingProvider]
) -> None:
    _EMBEDDING_PROVIDERS[name.lower()] = provider_cls


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
    key = name.lower()
    if key in _CHAT_PROVIDERS:
        return _CHAT_PROVIDERS[key]
    _discover_provider_loaders()
    loader = _PROVIDER_LOADERS.get(key)
    if loader and loader.chat:
        return _load_chat_provider(name, loader.chat)
    raise ValueError(f"Unsupported chat provider: {name}")


def get_embedding_provider(name: str) -> Type[EmbeddingProvider]:
    key = name.lower()
    if key in _EMBEDDING_PROVIDERS:
        return _EMBEDDING_PROVIDERS[key]
    _discover_provider_loaders()
    loader = _PROVIDER_LOADERS.get(key)
    if loader and loader.embedding:
        return _load_embedding_provider(name, loader.embedding)
    raise ValueError(f"Unsupported embedding provider: {name}")


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

    _discover_source_tree_provider_loaders()

    _PROVIDER_LOADERS_DISCOVERED = True


def _discover_source_tree_provider_loaders() -> None:
    pyproject_path = _find_pyproject_path()
    if pyproject_path is None:
        return

    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    provider_entry_points = (
        data.get("project", {}).get("entry-points", {}).get(_PROVIDER_ENTRY_POINT_GROUP)
        or {}
    )
    for entry_point_name, dotted_path in provider_entry_points.items():
        provider_name, surface = _parse_provider_entry_point_name(entry_point_name)
        if surface == "chat":
            _register_provider_loader(provider_name, chat=dotted_path)
        else:
            _register_provider_loader(provider_name, embedding=dotted_path)


def _find_pyproject_path() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        pyproject_path = parent / "pyproject.toml"
        if pyproject_path.is_file():
            return pyproject_path
    return None


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


def _load_chat_provider(name: str, dotted_path: str) -> Type[ChatProvider]:
    module_path, class_name = dotted_path.split(":", 1)
    try:
        module = import_module(module_path)
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            f"Chat provider '{name}' is registered but required dependencies are missing."
        ) from exc
    key = name.lower()
    if key in _CHAT_PROVIDERS:
        return _CHAT_PROVIDERS[key]
    provider_cls = getattr(module, class_name)
    _register_chat_provider(name, provider_cls)
    return provider_cls


def _load_embedding_provider(name: str, dotted_path: str) -> Type[EmbeddingProvider]:
    module_path, class_name = dotted_path.split(":", 1)
    try:
        module = import_module(module_path)
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            f"Embedding provider '{name}' is registered but required dependencies are missing."
        ) from exc
    key = name.lower()
    if key in _EMBEDDING_PROVIDERS:
        return _EMBEDDING_PROVIDERS[key]
    provider_cls = getattr(module, class_name)
    _register_embedding_provider(name, provider_cls)
    return provider_cls
