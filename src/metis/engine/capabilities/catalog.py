# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable
from functools import lru_cache
from importlib import metadata
from importlib.resources import files
from pathlib import Path
from typing import Any

from metis.configuration import load_yaml

from .contracts import CapabilityRegistration
from .manifest import CapabilityManifest

_BUILTIN_MANIFEST_PACKAGE = "metis.engine.capabilities.manifests"
_PACKAGE_REF_PREFIX = "package://"
CAPABILITY_ENTRY_POINT_GROUP = "metis.capabilities"


class CapabilityCatalog:
    def __init__(
        self,
        builtins: Iterable[CapabilityRegistration],
        entry_points: Iterable[metadata.EntryPoint] | None = None,
    ) -> None:
        builtin_registrations = tuple(builtins)
        self._registrations = {
            registration.manifest.name: registration
            for registration in builtin_registrations
        }
        if len(self._registrations) != len(builtin_registrations):
            raise ValueError("Built-in capability names must be unique")
        discovered = (
            metadata.entry_points().select(group=CAPABILITY_ENTRY_POINT_GROUP)
            if entry_points is None
            else entry_points
        )
        self._entry_points: dict[str, list[metadata.EntryPoint]] = {}
        for entry_point in discovered:
            if entry_point.name.isidentifier():
                self._entry_points.setdefault(entry_point.name, []).append(entry_point)

    def resolve(self, name: str) -> CapabilityRegistration:
        registration = self._registrations.get(name)
        candidates = self._entry_points.get(name, [])
        if registration is not None:
            if candidates:
                raise ValueError(
                    f"Installed capability {name!r} conflicts with a built-in capability"
                )
            return registration
        if not candidates:
            raise ValueError(f"Capability {name!r} is not registered")
        if len(candidates) > 1:
            raise ValueError(f"Multiple capability packages register {name!r}")
        try:
            loaded = candidates[0].load()
            registration = (
                loaded()
                if callable(loaded) and not isinstance(loaded, CapabilityRegistration)
                else loaded
            )
        except Exception as exc:
            raise RuntimeError(f"Capability {name!r} failed to load: {exc}") from exc
        if not isinstance(registration, CapabilityRegistration):
            raise TypeError(
                f"Capability entry point {name!r} did not return a "
                "CapabilityRegistration"
            )
        if registration.manifest.name != name:
            raise ValueError(
                f"Capability entry point {name!r} returned registration "
                f"{registration.manifest.name!r}"
            )
        self._registrations[name] = registration
        self._entry_points.pop(name, None)
        return registration


def _load_yaml_mapping(resource: Any) -> dict[str, Any]:
    with resource.open("r", encoding="utf-8") as handle:
        loaded = load_yaml(handle)
    if not isinstance(loaded, dict):
        raise ValueError(
            f"Capability manifest {resource.name!r} must contain a YAML mapping"
        )
    return loaded


@lru_cache(maxsize=1)
def get_builtin_capability_manifests() -> tuple[CapabilityManifest, ...]:
    manifest_dir = files(_BUILTIN_MANIFEST_PACKAGE)
    manifests = []
    for resource in sorted(manifest_dir.iterdir(), key=lambda item: item.name):
        if not resource.name.endswith((".yaml", ".yml")):
            continue
        manifests.append(CapabilityManifest.from_mapping(_load_yaml_mapping(resource)))
    return tuple(manifests)


def get_capability_manifest(name: str) -> CapabilityManifest | None:
    key = str(name or "").strip().lower()
    if not key:
        return None
    for manifest in get_builtin_capability_manifests():
        if manifest.name == key:
            return manifest
    return None


def get_capability_contract(
    manifest: CapabilityManifest, contract_name: str = "model"
) -> str:
    contract_ref = manifest.contracts.get(contract_name)
    if not contract_ref:
        return ""
    return _read_contract_ref(contract_ref)


def _read_contract_ref(contract_ref: str) -> str:
    ref = str(contract_ref or "").strip()
    if not ref:
        return ""
    if ref.startswith(_PACKAGE_REF_PREFIX):
        return _read_package_contract(ref.removeprefix(_PACKAGE_REF_PREFIX))

    path = Path(ref)
    candidates = [path]
    if not path.is_absolute():
        candidates.append(_source_root() / path)
    for candidate in candidates:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    return ""


def _read_package_contract(ref: str) -> str:
    package, separator, resource_name = ref.partition("/")
    if not separator or not package or not resource_name:
        return ""
    return files(package).joinpath(resource_name).read_text(encoding="utf-8")


def _source_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    return Path.cwd()
