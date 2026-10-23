# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Literal
from typing import get_args

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_TITLES = {value: value.capitalize() for value in get_args(Severity)}
SEVERITY_PRIORITY = {
    title: priority for priority, title in enumerate(SEVERITY_TITLES.values(), start=1)
}
SEVERITY_ALIASES = {
    "MED": "MEDIUM",
    "MID": "MEDIUM",
    "CRIT": "CRITICAL",
}
