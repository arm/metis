# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import re


def _extract_terms(text: str, *, limit: int = 6) -> list[str]:
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", text or "")
    stop = {
        "this",
        "that",
        "with",
        "from",
        "line",
        "file",
        "rule",
        "finding",
        "valid",
        "invalid",
        "code",
        "runtime",
        "check",
        "checks",
        "called",
        "function",
        "obsolete",
        "recommended",
        "later",
        "array",
        "length",
        "instead",
        "variable",
    }
    out: list[str] = []
    seen: set[str] = set()
    for tok in tokens:
        if tok.lower() in stop:
            continue
        if tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
        if len(out) >= limit:
            break
    return out


def _extract_call_like_identifiers(text: str, *, limit: int = 10) -> list[str]:
    names = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text or "")
    seen = set()
    out = []
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
        if len(out) >= limit:
            break
    return out


def _extract_referenced_paths(text: str, *, limit: int = 24) -> list[str]:
    refs: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        quoted = re.findall(r'["\']([A-Za-z0-9_./\\-]+\.[A-Za-z0-9_+-]+)["\']', line)
        for match in quoted:
            candidate = str(match).strip().replace("\\", "/")
            looks_reference = "/" in candidate or "." in candidate
            has_alpha = bool(re.search(r"[A-Za-z]", candidate))
            parts = candidate.split(".")
            looks_ipv4 = (
                len(parts) == 4
                and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p)
                and all(p for p in parts)
            )
            if (
                not candidate
                or not looks_reference
                or not has_alpha
                or looks_ipv4
                or candidate in seen
                or candidate.startswith("/")
                or candidate.startswith("../")
            ):
                continue
            seen.add(candidate)
            refs.append(candidate)
            if len(refs) >= limit:
                return refs
    return refs


def _build_related_paths(
    file_path: str, refs: list[str], *, limit: int = 12
) -> list[str]:
    related: list[str] = []
    seen: set[str] = set()
    base_dir = os.path.dirname(file_path or "")
    for ref in refs:
        candidates = [ref]
        if base_dir and ref.startswith("./"):
            candidates.append(os.path.join(base_dir, ref))
        for candidate in candidates:
            normalized = os.path.normpath(candidate).replace("\\", "/")
            if (
                not normalized
                or normalized in seen
                or normalized.startswith("../")
                or normalized.startswith("/")
            ):
                continue
            seen.add(normalized)
            related.append(normalized)
            if len(related) >= limit:
                return related
    return related


def _token_pattern(term: str) -> str:
    escaped = re.escape(term)
    return rf"(^|[^A-Za-z0-9_]){escaped}([^A-Za-z0-9_]|$)"


def _limit_output(text: str, *, max_lines: int = 120, max_chars: int = 5000) -> str:
    lines = (text or "").splitlines()
    if len(lines) > max_lines:
        clipped = "\n".join(lines[:max_lines]) + "\n...[truncated]"
    else:
        clipped = text or ""
    if len(clipped) > max_chars:
        return clipped[:max_chars] + "\n...[truncated]"
    return clipped


def _parse_grep_hits(output: str, *, max_hits: int = 12) -> list[tuple[str, int]]:
    seen: set[tuple[str, int]] = set()
    for raw in (output or "").splitlines():
        parts = raw.split(":", 2)
        if len(parts) < 3:
            continue
        path = parts[0].strip()
        try:
            line = int(parts[1].strip())
        except Exception:
            continue
        key = (path, line)
        if key in seen:
            continue
        seen.add(key)
    hits = sorted(seen, key=lambda h: (h[0].lower(), h[1]))
    if len(hits) > max_hits:
        hits = hits[:max_hits]
    return hits


def _extend_hits(
    current: list[tuple[str, int]],
    incoming: list[tuple[str, int]],
    *,
    max_total: int = 12,
) -> None:
    existing = set(current)
    for hit in incoming:
        if hit in existing:
            continue
        current.append(hit)
        existing.add(hit)
        if len(current) >= max_total:
            break
