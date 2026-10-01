# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import os
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


_C_ESCAPES = {
    "a": 7,
    "b": 8,
    "f": 12,
    "n": 10,
    "r": 13,
    "t": 9,
    "v": 11,
    '"': 34,
    "\\": 92,
}


def unquote_git_path(path: str) -> str:
    """Decode a C-quoted path from a git diff header."""
    if len(path) < 2 or not (path.startswith('"') and path.endswith('"')):
        return path
    body = path[1:-1]
    decoded = bytearray()
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\" or index + 1 >= len(body):
            decoded.extend(char.encode("utf-8"))
            index += 1
            continue
        escaped = body[index + 1]
        octal = body[index + 1 : index + 4]
        if len(octal) == 3 and all(digit in "01234567" for digit in octal):
            decoded.append(int(octal, 8) & 0xFF)
            index += 4
        elif escaped in _C_ESCAPES:
            decoded.append(_C_ESCAPES[escaped])
            index += 2
        else:
            decoded.extend(("\\" + escaped).encode("utf-8"))
            index += 2
    return os.fsdecode(bytes(decoded))
