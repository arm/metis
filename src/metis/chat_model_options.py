# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def merge_chat_model_kwargs(
    *sources: Mapping[str, Any] | None,
    model: Any = None,
    callbacks: Any = None,
    reasoning_effort: Any = None,
    response_format: Any = None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    for source in sources:
        if source:
            kwargs.update(source)
    if model is not None:
        kwargs["model"] = model
    if callbacks is not None:
        kwargs["callbacks"] = callbacks
    if response_format is not None:
        kwargs["response_format"] = response_format
    if reasoning_effort is not None:
        kwargs["reasoning_effort"] = reasoning_effort
    return {key: value for key, value in kwargs.items() if value is not None}
