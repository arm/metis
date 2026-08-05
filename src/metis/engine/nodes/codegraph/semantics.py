# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Mapping
from importlib import metadata
from threading import Lock
from threading import RLock

from metis.engine.codegraph import CodeGraphSemantics

from .provider import entry_point_cache_identity

CODEGRAPH_SEMANTICS_ENTRY_POINT_GROUP = "metis.codegraph_semantics"


class CodeGraphSemanticsCatalog:
    def __init__(
        self,
        entry_points: Iterable[metadata.EntryPoint] | None = None,
        *,
        providers: Mapping[str, CodeGraphSemantics] | None = None,
    ) -> None:
        self._providers = dict(providers or {})
        discovered = (
            metadata.entry_points().select(group=CODEGRAPH_SEMANTICS_ENTRY_POINT_GROUP)
            if entry_points is None
            else entry_points
        )
        self._entry_points: dict[str, list[metadata.EntryPoint]] = {}
        self._provider_locks: dict[str, Lock] = {}
        self._lock = RLock()
        for entry_point in discovered:
            self._entry_points.setdefault(entry_point.name, []).append(entry_point)

    def has(self, name: str | None) -> bool:
        if not name:
            return False
        try:
            self.resolve(name)
        except (RuntimeError, TypeError, ValueError):
            return False
        return True

    def contains(self, name: str | None) -> bool:
        if not name:
            return False
        with self._lock:
            return name in self._providers or name in self._entry_points

    def resolve(self, name: str) -> CodeGraphSemantics:
        with self._lock:
            provider = self._providers.get(name)
            if provider is not None:
                return provider
            candidates = self._entry_points.get(name, [])
            if not candidates:
                raise ValueError(f"Unknown CodeGraph semantics provider: {name!r}")
            if len(candidates) > 1:
                raise ValueError(
                    f"Multiple CodeGraph semantics packages register {name!r}"
                )
            try:
                loaded = candidates[0].load()
                provider = loaded() if callable(loaded) else loaded
            except Exception as exc:
                message = f"CodeGraph semantics provider {name!r} failed to load: {exc}"
                raise RuntimeError(message) from exc
            if not callable(getattr(provider, "analyze_node", None)):
                message = f"CodeGraph semantics provider {name!r} has no analyze_node"
                raise TypeError(message)
            self._providers[name] = provider
            return provider

    def provider_lock(self, name: str) -> Lock:
        with self._lock:
            return self._provider_locks.setdefault(name, Lock())

    def cache_identity(self, name: str | None) -> str:
        if not name:
            return ""
        candidates = self._entry_points.get(name, ())
        if candidates:
            identities = sorted(
                entry_point_cache_identity(entry) for entry in candidates
            )
            return "|".join(identities)
        return f"{name}:builtin" if name in self._providers else ""
