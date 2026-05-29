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

TRIAGE_NOISE_FILTER_GUIDANCE = f"""\
Metis triage filter, for internal decision-making only; do not output priority:
- Emit a finding only when it would be kept as a p0-p4 real security issue.
- Treat p2 as the default for a real, evidenced security issue unless the shown
  impact, exploitability, deployment scope, or mitigation evidence justifies
  higher urgency or lower practical impact.
- Return no finding for p5 cases: {TRIAGE_NOISE_FILTER_CRITERIA}.
- Do not report multiple findings for the same root cause; report the clearest
  representative only.
- Do not infer exploitability from CWE, dangerous API names, or graph
  reachability alone; tie the issue to attacker control, security impact, and
  the shown code.
"""
