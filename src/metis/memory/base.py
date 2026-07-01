# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Literal, Protocol

from langgraph.store.base import BaseStore
from langgraph.store.base import Item
from langgraph.store.base import SearchItem


Namespace = tuple[str, ...]
JsonValue = dict[str, Any]


class StoreLike(Protocol):
    def put(
        self,
        namespace: Namespace,
        key: str,
        value: JsonValue,
        index: Literal[False] | list[str] | None = None,
    ) -> None: ...

    def get(self, namespace: Namespace, key: str) -> Item | None: ...

    def search(
        self,
        namespace_prefix: Namespace,
        *,
        query: str | None = None,
        filter: dict[str, Any] | None = None,
        limit: int = 10,
        offset: int = 0,
    ) -> list[SearchItem]: ...

    def delete(self, namespace: Namespace, key: str) -> None: ...

    def list_namespaces(
        self,
        *,
        prefix: Namespace | None = None,
        suffix: Namespace | None = None,
        max_depth: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Namespace]: ...


__all__ = [
    "BaseStore",
    "Item",
    "JsonValue",
    "Namespace",
    "SearchItem",
    "StoreLike",
]
