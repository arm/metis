# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import fnmatch
import importlib
import inspect
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields
from importlib import metadata
from importlib.resources import files
from threading import RLock
from typing import Any

from metis.configuration import _deep_merge
from metis.configuration import load_yaml


logger = logging.getLogger("metis")

_PLUGIN_PACKAGE = "metis.plugins"
_LANGUAGE_PLUGIN_ENTRY_POINT_GROUP = "metis.language_plugins"


def _as_tuple(values: Iterable[Any] | None) -> tuple[str, ...]:
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)) or any(
        not isinstance(value, str) for value in values
    ):
        raise ValueError("Language plugin manifest lists must contain strings")
    return tuple(value.strip().lower() for value in values if value.strip())


def _normalise_resource(resource: str | None) -> str | None:
    if not resource:
        return None
    return str(resource).strip()


def _load_yaml_mapping(handle: Any, *, resource: str) -> dict[str, Any]:
    loaded = load_yaml(handle)
    if not isinstance(loaded, dict):
        raise ValueError(f"Plugin resource {resource!r} must contain a YAML mapping")
    return loaded


def _load_yaml_resource(resource: str) -> dict[str, Any]:
    if ":" in resource:
        package, name = resource.split(":", 1)
        target = files(package).joinpath(name)
    else:
        target = files(_PLUGIN_PACKAGE).joinpath(resource)
    with target.open("r", encoding="utf-8") as handle:
        return _load_yaml_mapping(handle, resource=resource)


def _matches_suffix_pattern(name: str, pattern: str) -> bool:
    if "*" not in pattern:
        return name.endswith(pattern)
    if pattern.count("*") == 1 and pattern.endswith("*"):
        return pattern[:-1] in name
    return fnmatch.fnmatch(name, pattern)


@dataclass(frozen=True, slots=True)
class LanguagePluginManifest:
    name: str
    implementation: str = ""
    config_resource: str = ""
    extensions: tuple[str, ...] = ()
    source_extensions: tuple[str, ...] = ()
    header_extensions: tuple[str, ...] = ()
    filename_patterns: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    capabilities: dict[str, Any] = field(default_factory=dict)
    prompt_profile: str | None = None
    priority: int = 0

    def __post_init__(self) -> None:
        for key in ("name", "implementation", "config_resource"):
            if not isinstance(getattr(self, key), str):
                raise ValueError(f"Language plugin manifest {key} must be a string")
        if self.prompt_profile is not None and not isinstance(self.prompt_profile, str):
            raise ValueError("Language plugin manifest prompt_profile must be a string")
        if isinstance(self.priority, bool) or not isinstance(self.priority, int):
            raise ValueError("Language plugin manifest priority must be an integer")
        if not isinstance(self.capabilities, Mapping) or any(
            not isinstance(key, str) or not isinstance(value, (Mapping, bool))
            for key, value in self.capabilities.items()
        ):
            raise ValueError(
                "Language plugin manifest capabilities must map names to booleans or mappings"
            )
        name = self.name.strip().lower()
        if not name:
            raise ValueError("Language plugin manifest name is required")
        object.__setattr__(self, "name", name)
        object.__setattr__(
            self,
            "implementation",
            str(self.implementation or "").strip(),
        )
        object.__setattr__(self, "extensions", _as_tuple(self.extensions))
        object.__setattr__(self, "source_extensions", _as_tuple(self.source_extensions))
        object.__setattr__(self, "header_extensions", _as_tuple(self.header_extensions))
        object.__setattr__(
            self,
            "filename_patterns",
            _as_tuple(self.filename_patterns),
        )
        aliases = _as_tuple(self.aliases) or (name,)
        object.__setattr__(self, "aliases", aliases)
        object.__setattr__(
            self,
            "capabilities",
            {
                key: dict(value) if isinstance(value, Mapping) else value
                for key, value in self.capabilities.items()
            },
        )
        self.codegraph_registration_name()
        config_resource = _normalise_resource(self.config_resource)
        if config_resource is None:
            raise ValueError(f"Language plugin manifest {name!r} needs config_resource")
        object.__setattr__(self, "config_resource", config_resource)
        if self.prompt_profile is not None:
            object.__setattr__(
                self,
                "prompt_profile",
                str(self.prompt_profile).strip() or None,
            )
        object.__setattr__(self, "priority", int(self.priority or 0))

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "LanguagePluginManifest":
        if not isinstance(data, Mapping):
            raise ValueError("Language plugin manifest must be a mapping")
        unknown = data.keys() - {item.name for item in fields(cls)}
        if unknown:
            raise ValueError(
                f"Unknown language plugin manifest settings: {', '.join(sorted(map(str, unknown)))}"
            )
        return cls(**{"name": "", **data})

    def with_overrides(self, data: Mapping[str, Any]) -> "LanguagePluginManifest":
        merged = {
            "name": self.name,
            "implementation": self.implementation,
            "extensions": self.extensions,
            "source_extensions": self.source_extensions,
            "header_extensions": self.header_extensions,
            "filename_patterns": self.filename_patterns,
            "aliases": self.aliases,
            "capabilities": self.capabilities,
            "config_resource": self.config_resource,
            "prompt_profile": self.prompt_profile,
            "priority": self.priority,
        }
        merged.update(data)
        return LanguagePluginManifest.from_mapping(merged)

    def codegraph_registration_name(self) -> str | None:
        capability = self.capabilities.get("codegraph", False)
        if not isinstance(capability, bool):
            raise ValueError(
                f"Language plugin manifest {self.name!r} must configure "
                "codegraph as a boolean"
            )
        if not capability:
            return None
        return self.name


class LanguagePluginHandle:
    def __init__(
        self,
        manifest: LanguagePluginManifest,
        *,
        plugin_config: Mapping[str, Any] | None = None,
    ):
        self.manifest = manifest
        self._plugin_config = dict(plugin_config or {})
        self._config: dict[str, Any] | None = None
        self._plugin: Any | None = None
        self._lock = RLock()

    def _load_profile(self, profile_name: str) -> dict[str, Any]:
        resource = (
            profile_name if ":" in profile_name else f"profiles/{profile_name}.yaml"
        )
        return _load_yaml_resource(resource)

    def _load_language_config(self) -> dict[str, Any]:
        loaded = _load_yaml_resource(self.manifest.config_resource)
        profile_name = str(
            loaded.pop("inherits", None) or self.manifest.prompt_profile or ""
        ).strip()
        if profile_name:
            loaded = _deep_merge(self._load_profile(profile_name), loaded)
        for section in ("splitting", "prompts"):
            if section in loaded and not isinstance(loaded[section], Mapping):
                raise ValueError(
                    f"Language plugin {self.manifest.name!r} resource "
                    f"{self.manifest.config_resource!r}: {section} must be a mapping"
                )
        loaded["supported_extensions"] = [
            *self.manifest.extensions,
            *self.manifest.filename_patterns,
        ]
        return loaded

    def config(self) -> dict[str, Any]:
        if self._config is None:
            with self._lock:
                if self._config is None:
                    self._config = self._load_language_config()
        return self._config

    def plugin_config(self) -> dict[str, Any]:
        return {
            "docs": dict(self._plugin_config.get("docs", {})),
            "general_prompts": dict(self._plugin_config.get("general_prompts", {})),
            "plugins": _LazyPluginSections(self),
        }

    def get_plugin(self) -> Any:
        if self._plugin is None:
            with self._lock:
                if self._plugin is None:
                    if not self.manifest.implementation:
                        from .base import ConfigBackedLanguagePlugin

                        self._plugin = ConfigBackedLanguagePlugin(
                            self.plugin_config(),
                            name=self.manifest.name,
                        )
                        logger.debug(
                            "Loaded config-backed language plugin for '%s'",
                            self.manifest.name,
                        )
                        return self._plugin
                    module_path, class_name = self.manifest.implementation.split(":", 1)
                    module = importlib.import_module(module_path)
                    target = getattr(module, class_name)
                    try:
                        signature = inspect.signature(target)
                    except (TypeError, ValueError):
                        self._plugin = target(self.plugin_config())
                    else:
                        plugin_config = self.plugin_config()
                        try:
                            signature.bind(plugin_config)
                        except TypeError:
                            signature.bind()
                            self._plugin = target()
                        else:
                            self._plugin = target(plugin_config)
                    logger.debug(
                        "Loaded language plugin module '%s' for '%s' using '%s'",
                        module_path,
                        self.manifest.name,
                        class_name,
                    )
        return self._plugin


class _LazyPluginSections(Mapping):
    def __init__(self, handle: LanguagePluginHandle):
        self._handle = handle

    def __iter__(self):
        yield self._handle.manifest.name

    def __len__(self):
        return 1

    def copy(self):
        return dict(self)

    def get(self, key, default=None):
        if str(key or "").lower() == self._handle.manifest.name:
            return self._handle.config()
        return default

    def __getitem__(self, key):
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __contains__(self, key):
        return str(key or "").lower() == self._handle.manifest.name


class LanguagePluginRegistry:
    def __init__(
        self,
        manifests: Iterable[LanguagePluginManifest | Mapping[str, Any]],
        *,
        plugin_config: Mapping[str, Any] | None = None,
    ):
        self._plugin_config = dict(plugin_config or {})
        self._handles: dict[str, LanguagePluginHandle] = {}
        self._logged_manifest_matches: set[str] = set()
        self._log_lock = RLock()
        for item in manifests:
            manifest = (
                item
                if isinstance(item, LanguagePluginManifest)
                else LanguagePluginManifest.from_mapping(item)
            )
            if manifest.name in self._handles:
                raise ValueError(f"Duplicate language plugin name {manifest.name!r}")
            self._handles[manifest.name] = LanguagePluginHandle(
                manifest,
                plugin_config=self._plugin_config,
            )

    def _log_manifest_match(self, manifest: LanguagePluginManifest, path: str) -> None:
        if not logger.isEnabledFor(logging.DEBUG):
            return
        with self._log_lock:
            if manifest.name in self._logged_manifest_matches:
                return
            self._logged_manifest_matches.add(manifest.name)
        logger.debug(
            "Matched language plugin manifest '%s' for path '%s'; module remains lazy until needed: %s",
            manifest.name,
            path,
            manifest.implementation or "metis.plugins.base:ConfigBackedLanguagePlugin",
        )

    @classmethod
    def from_config(
        cls,
        plugin_config: Mapping[str, Any] | None = None,
    ) -> "LanguagePluginRegistry":
        manifests = _load_builtin_manifests()
        manifests.extend(_load_entry_point_manifests())
        manifests = _resolve_manifest_name_conflicts(manifests)
        manifests = _apply_manifest_overrides(manifests, plugin_config or {})
        return cls(manifests, plugin_config=plugin_config)

    def _handle_for_name(self, name: str) -> LanguagePluginHandle | None:
        key = str(name or "").lower()
        handle = self._handles.get(key)
        if handle is not None:
            return handle
        manifest = _select_manifest(
            candidate.manifest
            for candidate in self._handles.values()
            if key in candidate.manifest.aliases
        )
        return self._handles[manifest.name] if manifest is not None else None

    def _manifests(self) -> list[LanguagePluginManifest]:
        return [handle.manifest for handle in self._handles.values()]

    def supported_language_names(self) -> list[str]:
        return sorted(manifest.name for manifest in self._manifests())

    def supported_code_extensions(self) -> list[str]:
        extensions = {
            extension
            for manifest in self._manifests()
            for extension in manifest.extensions
        }
        return sorted(extensions)

    def get_manifest(self, name: str) -> LanguagePluginManifest | None:
        handle = self._handle_for_name(name)
        if handle is None:
            return None
        return handle.manifest

    def get_manifest_for_extension(
        self, extension: str
    ) -> LanguagePluginManifest | None:
        ext = str(extension or "").lower()
        if not ext:
            return None
        matches = [
            manifest for manifest in self._manifests() if ext in manifest.extensions
        ]
        return _select_manifest(matches)

    def get_manifest_for_path(self, path: str) -> LanguagePluginManifest | None:
        path_text = str(path or "")
        extension = ""
        if "." in path_text:
            extension = "." + path_text.rsplit(".", 1)[1].lower()
        manifest = self.get_manifest_for_extension(extension)
        if manifest is not None:
            return manifest
        name = path_text.rsplit("/", 1)[-1].lower()
        matches = [
            manifest
            for manifest in self._manifests()
            for pattern in manifest.filename_patterns
            if _matches_suffix_pattern(name, pattern)
        ]
        return _select_manifest(matches)

    def get_plugin(self, name: str):
        handle = self._handle_for_name(name)
        if handle is None:
            return None
        return handle.get_plugin()

    def get_plugin_for_extension(self, extension: str):
        manifest = self.get_manifest_for_extension(extension)
        if manifest is None:
            return None
        return self._handles[manifest.name].get_plugin()

    def get_plugin_for_path(self, path: str):
        manifest = self.get_manifest_for_path(path)
        if manifest is None:
            return None
        return self._handles[manifest.name].get_plugin()

    def get_prompts_for_language(self, name: str) -> dict[str, Any]:
        handle = self._handle_for_name(name)
        if handle is None:
            return {}
        prompts = handle.config().get("prompts", {})
        return dict(prompts) if isinstance(prompts, Mapping) else {}

    def language_name_for_path(self, path: str) -> str | None:
        manifest = self.get_manifest_for_path(path)
        return manifest.name if manifest is not None else None

    def codegraph_registration_for_path(self, path: str) -> str | None:
        manifest = self.get_manifest_for_path(path)
        if manifest is None:
            return None
        registration = manifest.codegraph_registration_name()
        if registration is not None:
            self._log_manifest_match(manifest, path)
        return registration


def _select_manifest(
    manifests: Iterable[LanguagePluginManifest],
) -> LanguagePluginManifest | None:
    candidates = list(manifests)
    if not candidates:
        return None
    candidates.sort(
        key=lambda manifest: (manifest.priority, manifest.name),
        reverse=True,
    )
    top = candidates[0]
    tied = [
        manifest
        for manifest in candidates[1:]
        if manifest.priority == top.priority and manifest.name != top.name
    ]
    if tied:
        names = ", ".join(sorted({top.name, *(manifest.name for manifest in tied)}))
        raise ValueError(
            f"Ambiguous language plugin match at priority {top.priority}: {names}"
        )
    return top


def _load_builtin_manifests() -> list[LanguagePluginManifest]:
    manifest_dir = files(_PLUGIN_PACKAGE).joinpath("manifests")
    manifests = []
    for resource in sorted(manifest_dir.iterdir(), key=lambda item: item.name):
        if not resource.name.endswith((".yaml", ".yml")):
            continue
        manifests.append(
            LanguagePluginManifest.from_mapping(
                _load_yaml_resource(f"manifests/{resource.name}")
            )
        )
    return manifests


def _load_entry_point_manifests() -> list[LanguagePluginManifest]:
    try:
        eps = metadata.entry_points().select(group=_LANGUAGE_PLUGIN_ENTRY_POINT_GROUP)
    except Exception as exc:
        logger.debug("Language plugin entry point discovery failed: %s", exc)
        return []

    manifests = []
    for ep in eps:
        try:
            target = ep.load()
            loaded = target() if callable(target) else target
            manifests.append(
                loaded
                if isinstance(loaded, LanguagePluginManifest)
                else LanguagePluginManifest.from_mapping(loaded)
            )
        except Exception as exc:
            logger.warning(
                "Failed to load language plugin manifest '%s': %s",
                ep.name,
                exc,
            )
    return manifests


def _resolve_manifest_name_conflicts(
    manifests: list[LanguagePluginManifest],
) -> list[LanguagePluginManifest]:
    resolved: dict[str, LanguagePluginManifest] = {}
    for manifest in manifests:
        existing = resolved.get(manifest.name)
        if existing is not None:
            logger.warning(
                "Ignoring duplicate language plugin manifest '%s'; use "
                "language_plugins.%s in config to replace a built-in explicitly",
                manifest.name,
                manifest.name,
            )
            continue
        resolved[manifest.name] = manifest
    return list(resolved.values())


def _apply_manifest_overrides(
    manifests: list[LanguagePluginManifest],
    plugin_config: Mapping[str, Any],
) -> list[LanguagePluginManifest]:
    overrides = plugin_config.get("language_plugins", {})
    if not isinstance(overrides, Mapping):
        raise ValueError("language_plugins must be a mapping")

    overrides_by_name = {}
    for name, override in overrides.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("language_plugins keys must be non-empty names")
        if not isinstance(override, Mapping):
            raise ValueError(f"language_plugins.{name} must be a mapping")
        key = name.strip().lower()
        if "name" in override and (
            not isinstance(override["name"], str)
            or override["name"].strip().lower() != key
        ):
            raise ValueError(f"language_plugins.{name}.name must match {key!r}")
        if key in overrides_by_name:
            raise ValueError(f"Duplicate language plugin override {key!r}")
        overrides_by_name[key] = override
    existing_names = {manifest.name for manifest in manifests}
    resolved = []
    for manifest in manifests:
        override = overrides_by_name.get(manifest.name)
        if isinstance(override, Mapping):
            resolved.append(manifest.with_overrides(override))
        else:
            resolved.append(manifest)

    for name, override in overrides_by_name.items():
        if name in existing_names:
            continue
        data = dict(override)
        data.setdefault("name", name)
        resolved.append(LanguagePluginManifest.from_mapping(data))
    return resolved
