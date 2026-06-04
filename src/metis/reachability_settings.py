# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from typing import Any

DEFAULT_REACHABILITY_MAX_PATHS = 0
DEFAULT_REACHABILITY_MAX_PATHS_PER_SINK = 3
DEFAULT_REACHABILITY_MAX_PATH_LENGTH = 25
DEFAULT_REACHABILITY_DOMAIN_PROFILES = ("gpu",)

REACHABILITY_CONFIG_KEYS = tuple(
    "reachability_confirmation_model reachability_max_paths "
    "reachability_max_paths_per_sink reachability_max_path_length "
    "reachability_reasoning_effort reachability_source_functions "
    "reachability_security_functions reachability_domain_profiles "
    "reachability_domain_hints".split()
)


def collect_reachability_config(
    config: Mapping[str, Any], engine_config: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    engine_config = engine_config or {}
    reachability_config = {}
    for key in REACHABILITY_CONFIG_KEYS:
        if key in config:
            reachability_config[key] = config[key]
        elif key in engine_config:
            reachability_config[key] = engine_config[key]
    return reachability_config


def coerce_reachability_settings(
    config: Mapping[str, Any] | None, *, default_workers: int
) -> dict[str, Any]:
    config = config or {}
    domain_profiles = config.get("reachability_domain_profiles")
    if domain_profiles is None:
        domain_profiles = list(DEFAULT_REACHABILITY_DOMAIN_PROFILES)

    return {
        "confirmation_model": config.get("reachability_confirmation_model"),
        "max_workers": default_workers,
        "max_paths": _int_config(
            config, "reachability_max_paths", DEFAULT_REACHABILITY_MAX_PATHS
        ),
        "max_paths_per_sink": _int_config(
            config,
            "reachability_max_paths_per_sink",
            DEFAULT_REACHABILITY_MAX_PATHS_PER_SINK,
        ),
        "max_path_length": _int_config(
            config,
            "reachability_max_path_length",
            DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
        ),
        "reasoning_effort": config.get("reachability_reasoning_effort"),
        "source_functions": config.get("reachability_source_functions") or [],
        "security_functions": config.get("reachability_security_functions") or [],
        "domain_profiles": domain_profiles,
        "domain_hints": config.get("reachability_domain_hints") or [],
    }


def _int_config(config: Mapping[str, Any], key: str, default: int) -> int:
    value = config.get(key)
    if value is None or value == "":
        return default
    return int(value)
