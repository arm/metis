# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from metis.utils import parse_json_output


def parse_records(
    raw: Any, *, response_model: type[BaseModel]
) -> list[dict[str, Any]] | None:
    if isinstance(raw, BaseModel):
        data = raw.model_dump()
    elif isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        data = parse_json_output(raw)
    else:
        return None

    try:
        return response_model.model_validate(data).model_dump()["records"]
    except (TypeError, ValueError):
        return None
