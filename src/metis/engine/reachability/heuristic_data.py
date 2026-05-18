# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Compact literal parsers for reachability heuristic data."""

from __future__ import annotations


def _words(text):
    return frozenset(str(text).split())
