# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field
import os

CopyKeySpec = tuple[str, ...] | Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class ApiKeySources:
    required: bool = False
    config_keys: tuple[str, ...] = ("api_key",)
    config_env_keys: tuple[str, ...] = ("api_key_env",)
    env_vars: tuple[str, ...] = ()
    optional_when: tuple[str, object] | None = None


@dataclass(frozen=True)
class ProviderConfigSpec:
    display_name: str
    required_keys: tuple[str, ...] = ()
    api_key: ApiKeySources = field(default_factory=ApiKeySources)
    copy_keys: CopyKeySpec = ()


def build_provider_config(
    *,
    provider_name: str,
    provider_cls: type,
    raw_config: Mapping[str, object],
    section: str,
) -> dict[str, object]:
    spec = _provider_config_spec(provider_name, provider_cls, section)
    provider_config = dict(raw_config)
    _validate_required_keys(
        provider_config=provider_config,
        spec=spec,
        section=section,
    )

    config = _copy_provider_config(provider_config, spec)
    api_key = _resolve_api_key(
        provider_config=provider_config,
        spec=spec,
        section=section,
    )
    if api_key:
        config["api_key"] = api_key

    return _compact_provider_config(config)


def _provider_config_spec(
    provider_name: str, provider_cls: type, section: str
) -> ProviderConfigSpec:
    spec = getattr(provider_cls, "CONFIG_SPEC", None)
    if isinstance(spec, ProviderConfigSpec):
        return spec
    raise ValueError(
        f"{provider_name} is registered as a {section} provider but does not define "
        "CONFIG_SPEC."
    )


def _validate_required_keys(
    *,
    provider_config: Mapping[str, object],
    spec: ProviderConfigSpec,
    section: str,
) -> None:
    missing_keys = [
        key for key in spec.required_keys if _is_missing(provider_config.get(key))
    ]
    if not missing_keys:
        return

    missing = ", ".join(f"{section}.{key}" for key in missing_keys)
    required_text = ", ".join(f"{section}.{key}" for key in spec.required_keys)
    raise ValueError(
        f"{spec.display_name} provider requires additional metis.yaml configuration. "
        f"Missing: {missing}. Required keys: {required_text}."
    )


def _resolve_api_key(
    *,
    provider_config: Mapping[str, object],
    spec: ProviderConfigSpec,
    section: str,
) -> str:
    sources = spec.api_key
    for config_key in sources.config_keys:
        value = provider_config.get(config_key)
        if isinstance(value, str) and value.strip():
            return value

    for config_env_key in sources.config_env_keys:
        env_var = provider_config.get(config_env_key)
        if isinstance(env_var, str) and env_var.strip():
            value = os.environ.get(env_var)
            if value:
                return value

    for env_var in sources.env_vars:
        value = os.environ.get(env_var)
        if value:
            return value

    if not sources.required or _optional_condition_matches(
        provider_config, sources.optional_when
    ):
        return ""

    source_descriptions = [
        f"{env_var} environment variable" for env_var in sources.env_vars
    ]
    source_descriptions.extend(f"{section}.{key}" for key in sources.config_keys)
    source_descriptions.extend(
        f"environment variable named by {section}.{key}"
        for key in sources.config_env_keys
    )
    sources_text = " or ".join(source_descriptions)
    raise RuntimeError(
        f"{sources_text} is required for {spec.display_name} provider but not set."
    )


def _copy_provider_config(
    provider_config: Mapping[str, object], spec: ProviderConfigSpec
) -> dict[str, object]:
    config: dict[str, object] = {}
    for output_key, sources in _copy_key_sources(spec.copy_keys):
        value = _first_value(provider_config, sources)
        if _is_missing(value):
            continue
        config[output_key] = value
    return config


def _copy_key_sources(copy_keys: CopyKeySpec):
    if isinstance(copy_keys, Mapping):
        return copy_keys.items()
    return ((key, (key,)) for key in copy_keys)


def _first_value(
    provider_config: Mapping[str, object], sources: tuple[str, ...]
) -> object | None:
    for source in sources:
        value: object | None
        if source.startswith("env:"):
            value = os.environ.get(source.removeprefix("env:"))
        elif source in provider_config:
            value = provider_config[source]
        else:
            continue
        if not _is_missing(value):
            return value
    return None


def _optional_condition_matches(
    provider_config: Mapping[str, object],
    optional_when: tuple[str, object] | None,
) -> bool:
    if optional_when is None:
        return False
    key, expected_value = optional_when
    return provider_config.get(key) == expected_value


def _compact_provider_config(config: Mapping[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in config.items()
        if value is not None and value != "" and value != {}
    }


def _is_missing(value: object) -> bool:
    return value is None or value == "" or value == {}
