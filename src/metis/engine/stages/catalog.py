# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable
from importlib import metadata

from .contracts import StageRegistration

EXECUTION_STAGE_ENTRY_POINT_GROUP = "metis.execution_stages"


class StageCatalog:
    def __init__(
        self,
        builtins: Iterable[str],
        entry_points: Iterable[metadata.EntryPoint] | None = None,
    ) -> None:
        builtin_names = tuple(builtins)
        self._builtin_names = frozenset(builtin_names)
        if len(self._builtin_names) != len(builtin_names):
            raise ValueError("Built-in execution stage names must be unique")
        discovered = (
            metadata.entry_points().select(group=EXECUTION_STAGE_ENTRY_POINT_GROUP)
            if entry_points is None
            else entry_points
        )
        self._registrations: dict[str, StageRegistration] = {}
        self._entry_points: dict[str, list[metadata.EntryPoint]] = {}
        for entry_point in discovered:
            if entry_point.name.isidentifier():
                self._entry_points.setdefault(entry_point.name, []).append(entry_point)
        collisions = self._builtin_names & self._entry_points.keys()
        if collisions:
            name = sorted(collisions)[0]
            raise ValueError(
                f"Installed execution stage {name!r} conflicts with a built-in stage"
            )

    def resolve(self, name: str) -> StageRegistration:
        if name in self._registrations:
            return self._registrations[name]
        candidates = self._entry_points.get(name, [])
        if name in self._builtin_names:
            raise ValueError(f"Execution stage {name!r} is built in")
        if not candidates:
            raise ValueError(f"Execution stage {name!r} is not registered")
        if len(candidates) > 1:
            raise ValueError(f"Multiple execution stage packages register {name!r}")
        try:
            loaded = candidates[0].load()
            registration = (
                loaded()
                if callable(loaded) and not isinstance(loaded, StageRegistration)
                else loaded
            )
        except Exception as exc:
            raise RuntimeError(
                f"Execution stage {name!r} failed to load: {exc}"
            ) from exc
        if not isinstance(registration, StageRegistration):
            raise TypeError(
                f"Execution stage entry point {name!r} did not return a "
                "StageRegistration"
            )
        if registration.name != name:
            raise ValueError(
                f"Execution stage entry point {name!r} returned registration "
                f"{registration.name!r}"
            )
        self._registrations[name] = registration
        self._entry_points.pop(name, None)
        return registration
