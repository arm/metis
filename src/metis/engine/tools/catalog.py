# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from .manifest import ToolManifest

_BUILTIN_MANIFEST_PACKAGE = "metis.engine.tools.manifests"
_PACKAGE_REF_PREFIX = "package://"


def _load_yaml_mapping(resource: Any) -> dict[str, Any]:
    with resource.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Tool manifest {resource.name!r} must contain a YAML mapping")
    return loaded


@lru_cache(maxsize=1)
def get_builtin_tool_manifests() -> tuple[ToolManifest, ...]:
    manifest_dir = files(_BUILTIN_MANIFEST_PACKAGE)
    manifests = []
    for resource in sorted(manifest_dir.iterdir(), key=lambda item: item.name):
        if not resource.name.endswith((".yaml", ".yml")):
            continue
        manifests.append(ToolManifest.from_mapping(_load_yaml_mapping(resource)))
    return tuple(manifests)


def get_tool_manifest(name: str) -> ToolManifest | None:
    key = str(name or "").strip().lower()
    if not key:
        return None
    for manifest in get_builtin_tool_manifests():
        if manifest.name == key:
            return manifest
    return None


def get_tool_contract(name: str, contract_name: str = "model") -> str:
    manifest = get_tool_manifest(name)
    if manifest is None:
        return ""
    contract_ref = manifest.contracts.get(contract_name)
    if not contract_ref:
        return ""
    return _read_contract_ref(contract_ref)


def get_tool_config(name: str) -> dict[str, Any]:
    manifest = get_tool_manifest(name)
    return deepcopy(manifest.config) if manifest is not None else {}


def get_active_tool_manifests() -> tuple[ToolManifest, ...]:
    return tuple(
        manifest for manifest in get_builtin_tool_manifests() if manifest.active
    )


def known_engine_tools() -> tuple[str, ...]:
    return tuple(sorted(manifest.name for manifest in get_active_tool_manifests()))


def planned_engine_tools() -> tuple[str, ...]:
    return tuple(
        sorted(
            manifest.name
            for manifest in get_builtin_tool_manifests()
            if not manifest.active
        )
    )


def default_engine_tools() -> tuple[str, ...]:
    return tuple(
        sorted(
            manifest.name
            for manifest in get_active_tool_manifests()
            if manifest.default_enabled
        )
    )


def format_known_engine_tools() -> str:
    return ", ".join(known_engine_tools())


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
