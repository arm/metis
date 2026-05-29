# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Shared prompt guidance for reachability review."""

TRIAGE_NOISE_FILTER_CRITERIA = (
    "false positives, duplicates, wrong code interpretation, non-exploitable "
    "code-quality issues, missing prerequisites, reliability-only crashes, "
    "generic internal-helper validation gaps, unchecked allocation failures, "
    "development-only configuration issues, theoretical resource exhaustion, "
    "or findings without a realistic attacker-controlled path and security impact"
)
