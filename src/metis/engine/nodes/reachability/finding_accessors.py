# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from .finding_values import _safe_int


def _first_attr(obj, *names):
    for name in names:
        value = getattr(obj, name, "")
        if value:
            return value
    return ""


def _finding_file(f):
    return _first_attr(f, "primary_file", "sink_file", "source_file")


def _finding_function(f):
    return _first_attr(f, "primary_function", "sink_function", "source_function")


def _finding_line(f):
    return _safe_int(
        getattr(f, "primary_line", 0)
        or getattr(f, "sink_line", 0)
        or getattr(f, "source_line", 0),
        0,
    )
