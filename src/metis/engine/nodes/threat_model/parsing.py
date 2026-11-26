# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from metis.engine.llm_runner import coerce_response_model


def parse_records(
    raw: Any, *, response_model: type[BaseModel]
) -> list[dict[str, Any]] | None:
    if isinstance(raw, BaseModel):
        raw = raw.model_dump()
    model = coerce_response_model(raw, response_model)
    return None if model is None else model.model_dump()["records"]
