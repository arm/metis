# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from importlib import metadata
from typing import Mapping
from metis.engine.codegraph import CodeGraphProvider
from metis.engine.codegraph import CodeGraphProviderContext
from metis.engine.codegraph import CodeGraphProviderFactory

CODEGRAPH_PROVIDER_ENTRY_POINT_GROUP = "metis.codegraph_providers"


def discover_provider_factories(
    builtins: Mapping[str, CodeGraphProviderFactory] | None = None,
) -> Mapping[str, CodeGraphProviderFactory]:
    factories = {
        normalize_provider_name(name): factory
        for name, factory in (builtins or {}).items()
    }
    entry_points = metadata.entry_points().select(
        group=CODEGRAPH_PROVIDER_ENTRY_POINT_GROUP
    )
    for entry_point in entry_points:
        key = normalize_provider_name(entry_point.name)
        if key in factories:
            raise ValueError(
                f"CodeGraph provider factory already registered for: {key}"
            )
        factories[key] = _lazy_entry_point_factory(key, entry_point)
    return factories


def normalize_provider_name(name: str) -> str:
    key = str(name).strip().lower()
    if not key:
        raise ValueError("CodeGraph provider name must not be empty")
    return key


def _lazy_entry_point_factory(
    name: str,
    entry_point: metadata.EntryPoint,
) -> CodeGraphProviderFactory:
    def create(context: CodeGraphProviderContext) -> CodeGraphProvider:
        factory = entry_point.load()
        if not callable(factory):
            raise TypeError(f"CodeGraph provider factory {name!r} is not callable")
        return factory(context)

    setattr(
        create,
        "__metis_cache_identity__",
        entry_point_cache_identity(entry_point),
    )
    return create


def entry_point_cache_identity(entry_point: metadata.EntryPoint) -> str:
    distribution = getattr(entry_point, "dist", None)
    version = str(getattr(distribution, "version", "") or "")
    value = str(getattr(entry_point, "value", "") or entry_point.name)
    return f"{value}@{version}"
