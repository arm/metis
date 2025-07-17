# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import hashlib


def read_file_lines(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.readlines()
    except Exception:
        return ["<source unavailable>"]


def create_fingerprint(file_path, line_number, rule_id):
    key = f"{file_path}:{line_number}:{rule_id}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()
