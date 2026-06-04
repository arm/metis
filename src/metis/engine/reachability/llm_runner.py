# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from metis.utils import parse_json_output


def reachability_response_payload(raw):
    if hasattr(raw, "model_dump"):
        return raw.model_dump()
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        parsed = parse_json_output(raw)
        return parsed if isinstance(parsed, dict) else None
    return None
