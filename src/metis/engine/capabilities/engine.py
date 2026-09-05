# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterator, Mapping
from types import MappingProxyType
from threading import RLock

from .catalog import CapabilityCatalog
from .contracts import CapabilityCloser
from .contracts import CapabilityContext
from .manifest import CapabilityManifest


class EngineCapabilities(Mapping[str, object]):
    def __init__(
        self,
        selected: set[str],
        configurations: Mapping[str, Mapping[str, object]],
        catalog: CapabilityCatalog,
        context: CapabilityContext,
    ) -> None:
        self._selected = frozenset(selected)
        self._configurations = MappingProxyType(dict(configurations))
        self._catalog = catalog
        self._context = context
        self._instances: dict[str, object] = {}
        self._constructing: set[str] = set()
        self._closers: list[tuple[object, CapabilityCloser]] = []
        self._lock = RLock()
        self._closed = False

    def __getitem__(self, name: str) -> object:
        if name not in self._selected:
            raise KeyError(name)
        return self._construct(name)

    def __iter__(self) -> Iterator[str]:
        return iter(self._selected)

    def __len__(self) -> int:
        return len(self._selected)

    def require(self, name: str) -> object:
        return self._construct(name)

    def manifest(self, name: str) -> CapabilityManifest:
        with self._lock:
            return self._catalog.resolve(name).manifest

    def _construct(self, name: str) -> object:
        with self._lock:
            if self._closed:
                raise RuntimeError("Engine capabilities are closed")
            if name in self._instances:
                return self._instances[name]
            if name in self._constructing:
                raise RuntimeError(f"Capability {name!r} is already being constructed")
            self._constructing.add(name)
            try:
                registration = self._catalog.resolve(name)
                configuration = registration.configuration.model_validate(
                    self._configurations.get(name, {})
                )
                instance = registration.factory(self._context, configuration)
            finally:
                self._constructing.remove(name)
            if instance is None:
                raise TypeError(f"Capability {name!r} factory returned None")
            if self._closed:
                error = RuntimeError(
                    f"Capability {name!r} was constructed after its owner closed"
                )
                if registration.close is not None:
                    try:
                        registration.close(instance)
                    except BaseException as cleanup_error:
                        error.add_note(
                            f"Capability cleanup also failed: {cleanup_error}"
                        )
                raise error
            self._instances[name] = instance
            if registration.close is not None:
                self._closers.append((instance, registration.close))
            return instance

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            closers, self._closers = self._closers, []
        first_error: BaseException | None = None
        for instance, close in reversed(closers):
            try:
                close(instance)
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error


def build_engine_capabilities(
    names: set[str],
    configurations: Mapping[str, Mapping[str, object]],
    catalog: CapabilityCatalog,
    context: CapabilityContext,
) -> EngineCapabilities:
    return EngineCapabilities(names, configurations, catalog, context)
