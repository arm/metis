# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable
from importlib import metadata
from .contracts import NodeRegistration
from .contracts import StageName

EXECUTION_NODE_ENTRY_POINT_GROUP = "metis.execution_nodes"


class NodeCatalog:
    def __init__(
        self,
        builtins: Iterable[NodeRegistration],
        entry_points: Iterable[metadata.EntryPoint] | None = None,
    ) -> None:
        self._registrations: dict[tuple[StageName, str], NodeRegistration] = {}
        for registration in builtins:
            self._add(registration)
        discovered = (
            metadata.entry_points().select(group=EXECUTION_NODE_ENTRY_POINT_GROUP)
            if entry_points is None
            else entry_points
        )
        self._entry_points: dict[tuple[StageName, str], list[metadata.EntryPoint]] = {}
        for entry_point in discovered:
            key = _entry_point_key(entry_point.name)
            if key is not None:
                self._entry_points.setdefault(key, []).append(entry_point)

    def resolve(self, stage: StageName, name: str) -> NodeRegistration:
        key = (stage, name)
        registration = self._registrations.get(key)
        candidates = self._entry_points.get(key, [])
        if registration is not None:
            if candidates:
                raise ValueError(
                    f"Installed execution node {stage}.{name} conflicts with a "
                    "built-in node"
                )
            return registration
        if not candidates:
            raise ValueError(
                f"Execution node {name!r} is not registered for stage {stage!r}"
            )
        if len(candidates) > 1:
            raise ValueError(f"Multiple execution node packages register {name!r}")
        try:
            loaded = candidates[0].load()
            registration = (
                loaded()
                if callable(loaded) and not isinstance(loaded, NodeRegistration)
                else loaded
            )
        except Exception as exc:
            raise RuntimeError(
                f"Execution node {stage}.{name} failed to load: {exc}"
            ) from exc
        if not isinstance(registration, NodeRegistration):
            raise TypeError(
                f"Execution node entry point {name!r} did not return a NodeRegistration"
            )
        if registration.name != name or registration.stage != stage:
            raise ValueError(
                f"Execution node entry point {name!r} returned registration "
                f"{registration.stage}.{registration.name}"
            )
        self._add(registration)
        self._entry_points.pop(key, None)
        return registration

    def _add(self, registration: NodeRegistration) -> None:
        key = (registration.stage, registration.name)
        if key in self._registrations:
            raise ValueError(
                f"Execution node {registration.stage}.{registration.name} "
                "is already registered"
            )
        self._registrations[key] = registration


def _entry_point_key(name: str) -> tuple[StageName, str] | None:
    prefix, separator, node_name = name.partition(".")
    if separator and prefix.isidentifier() and node_name.isidentifier():
        return prefix, node_name
    return None
