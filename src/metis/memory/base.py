# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Literal, Protocol

from langgraph.store.base import BaseStore
from langgraph.store.base import Item
from langgraph.store.base import Op
from langgraph.store.base import Result
from langgraph.store.base import SearchItem


Namespace = tuple[str, ...]
JsonValue = dict[str, Any]


def _validate_namespace(namespace: Namespace, *, allow_empty: bool = False) -> None:
    if not isinstance(namespace, tuple):
        raise ValueError("Memory namespace must be a tuple of string labels")
    if not namespace and not allow_empty:
        raise ValueError("Memory namespace cannot be empty")
    if any(
        not isinstance(label, str) or not label or "." in label for label in namespace
    ):
        raise ValueError(
            "Memory namespace labels must be non-empty strings without periods"
        )
    if namespace and namespace[0] == "langgraph":
        raise ValueError('Memory namespace root cannot be "langgraph"')


class StoreLike(Protocol):
    def batch(self, ops: Iterable[Op]) -> list[Result]: ...

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
