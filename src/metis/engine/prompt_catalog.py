# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from functools import cache
from importlib.resources import as_file
from importlib.resources import files
from types import MappingProxyType

from metis.configuration import load_yaml


@cache
def get_engine_prompts(name: str) -> Mapping[str, str]:
    resource = files("metis.engine").joinpath("prompts", f"{name}.yaml")
    with as_file(resource) as path:
        payload = load_yaml(path)
    if not isinstance(payload, dict):
        raise TypeError(f"Engine prompt resource {name!r} must contain a mapping")

    prompts: dict[str, str] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError(
                f"Engine prompt resource {name!r} must map names to strings"
            )
        prompts[key] = value
    return MappingProxyType(prompts)
