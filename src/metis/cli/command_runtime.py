# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class CommandRuntime:
    command: str
    command_args: list[str]
    use_retrieval_context: bool
    no_index_warning_emitted: bool = False
