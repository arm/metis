# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re

_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def extract_code_like_symbols(*texts: str, limit: int = 12) -> list[str]:
    symbols: list[str] = []
    seen: set[str] = set()
    for text in texts:
        for token in _IDENT_RE.findall(text or ""):
            if token in seen:
                continue
            seen.add(token)
            symbols.append(token)
            if len(symbols) >= limit:
                return symbols
    return symbols


def extract_c_family_seed_symbols(
    snippet: str,
    rule_id: str,
    file_path: str,
    *,
    limit: int = 20,
) -> list[str]:
    # Prefer symbols from code snippet, then rule id / path fragments.
    path_tokens = re.split(r"[^A-Za-z0-9_]+", file_path or "")
    return extract_code_like_symbols(
        snippet or "", rule_id or "", " ".join(path_tokens), limit=limit
    )
