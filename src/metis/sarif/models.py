# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict


class SarifPayload(BaseModel):
    version: Literal["2.1.0"]
    runs: tuple[dict[str, Any], ...]

    model_config = ConfigDict(extra="allow", frozen=True)
