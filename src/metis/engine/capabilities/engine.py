# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterator, Mapping
from types import MappingProxyType

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
        self._closers: list[tuple[object, CapabilityCloser]] = []

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
        return self._catalog.resolve(name).manifest

    def _construct(self, name: str) -> object:
        instance = self._instances.get(name)
        if instance is not None:
            return instance
        registration = self._catalog.resolve(name)
        configuration = registration.configuration.model_validate(
            self._configurations.get(name, {})
        )
        instance = registration.factory(self._context, configuration)
        self._instances[name] = instance
        if registration.close is not None:
            self._closers.append((instance, registration.close))
        return instance

    def close(self) -> None:
        first_error: Exception | None = None
        for instance, close in reversed(self._closers):
            try:
                close(instance)
            except Exception as exc:
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
