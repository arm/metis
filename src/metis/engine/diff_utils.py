# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from typing import Any


def extract_content_from_diff(file_diff: Any) -> str:
    content_lines = []
    for hunk in file_diff:
        for line in hunk:
            if line.is_added:
                content_lines.append(line.value)
    return "".join(content_lines)


def process_diff_file(file_diff: Any) -> str:
    changed_lines = []
    for hunk in file_diff:
        for line in hunk:
            if line.is_added:
                changed_lines.append("+" + line.value)
            elif line.is_removed:
                changed_lines.append("-" + line.value)
    return "".join(changed_lines)
