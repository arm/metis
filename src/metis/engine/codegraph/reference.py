# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import PositiveInt

from .provider import CodeGraphDiagnostic


class CodeGraphReference(BaseModel):
    revision: PositiveInt
    fingerprint: str = Field(min_length=1)
    producer_version: str = Field(min_length=1)
    failed_files: tuple[str, ...] = ()
    diagnostics: tuple[CodeGraphDiagnostic, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)
