# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
import re


def extract_code_like_symbols(*texts: str, limit: int = 20) -> list[str]:
    """Extract code-shaped identifiers from free-form text."""
    out: list[str] = []
    seen = set()

    def push(token: str) -> bool:
        tok = str(token or "").strip()
        if not tok or tok in seen:
            return False
        seen.add(tok)
        out.append(tok)
        return len(out) >= limit

    for text in texts:
        if not text:
            continue
        for tok in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
            if push(tok):
                return out
        for tok in re.findall(r"\b([A-Z][A-Z0-9_]{2,})\b", text):
            if push(tok):
                return out
        for tok in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*_[A-Za-z0-9_]+)\b", text):
            if push(tok):
                return out
    return out


def extract_c_family_seed_symbols(*texts: str, limit: int = 20) -> list[str]:
    """
    Deterministically extract likely C/C++ symbols/macros/call targets from
    finding text/snippet without generic prose-token heuristics.
    """
    return extract_code_like_symbols(*texts, limit=limit)


def parse_includes_from_text(text: str) -> list[str]:
    out: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line.startswith("#include"):
            continue
        quoted = re.findall(r'#include\s*"([^"]+)"', line)
        if quoted:
            out.extend(quoted)
            continue
        angled = re.findall(r"#include\s*<([^>]+)>", line)
        if angled:
            out.extend(angled)
    return out


def resolve_include_path(
    *, include: str, current_path: Path, root: Path
) -> Path | None:
    candidate = include.strip()
    if not candidate:
        return None
    local = (current_path.parent / candidate).resolve()
    if local.is_file():
        return local
    rooted = (root / candidate).resolve()
    if rooted.is_file():
        return rooted
    return None
