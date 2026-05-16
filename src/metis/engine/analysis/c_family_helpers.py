# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
import re

from metis.plugins.c_plugin import CPlugin
from metis.plugins.cpp_plugin import CppPlugin

_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_LOW_VALUE_C_FAMILY_PROBE_TERMS = {
    "c",
    "cc",
    "cpp",
    "cxx",
    "h",
    "hh",
    "hpp",
    "hxx",
}
CPP_EXTENSIONS = frozenset(CppPlugin.DEFAULT_EXTENSIONS)
C_FAMILY_EXTENSIONS = frozenset(
    CPlugin.DEFAULT_EXTENSIONS + CppPlugin.DEFAULT_EXTENSIONS
)
C_FAMILY_XREF_EXTENSIONS = frozenset((*C_FAMILY_EXTENSIONS, ".S", ".s"))


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
    return extract_code_like_symbols(snippet or "", limit=limit)


def is_low_value_c_family_probe_term(term: str) -> bool:
    text = str(term or "").strip().lower()
    if not text:
        return False
    return text in _LOW_VALUE_C_FAMILY_PROBE_TERMS


def is_c_family_file_path(file_path: str) -> bool:
    ext = Path(file_path or "").suffix.lower()
    return ext in C_FAMILY_EXTENSIONS


def is_c_family_xref_file_path(file_path: str) -> bool:
    ext = Path(file_path or "").suffix
    return ext in C_FAMILY_XREF_EXTENSIONS


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
