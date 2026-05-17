# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Compact literal parsers for reachability heuristic data."""

from __future__ import annotations


def _words(text):
    return frozenset(str(text).split())


def _mapping(text):
    tokens = str(text).split()
    if len(tokens) % 2:
        raise ValueError("mapping literals must contain key/value pairs")
    return {tokens[i]: tokens[i + 1] for i in range(0, len(tokens), 2)}
