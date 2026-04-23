# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib


def normalize_retrieved_doc(doc):
    content = str(getattr(doc, "page_content", "") or "")
    meta = getattr(doc, "metadata", {}) or {}
    source = str(
        meta.get("file_path")
        or meta.get("source")
        or meta.get("file_name")
        or meta.get("doc_id")
        or ""
    )
    raw_line = meta.get("line") or meta.get("start_line") or meta.get("line_number")
    try:
        line = int(raw_line)
    except Exception:
        line = 0
    digest = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
    return source, line, content, digest


def retrieve_context_deterministic(
    retriever,
    query: str,
    *,
    max_chars: int,
) -> str:
    if retriever is None:
        return ""
    try:
        docs = retriever.get_relevant_documents(query) or []
    except Exception:
        return ""

    normalized = [normalize_retrieved_doc(doc) for doc in docs]
    seen = set()
    ordered = []
    for source, line, content, digest in normalized:
        key = (source, line, digest)
        if key in seen:
            continue
        seen.add(key)
        ordered.append((source, line, content, digest))

    parts: list[str] = []
    used = 0
    for source, line, content, _digest in ordered:
        label = source if source else "<unknown>"
        line_label = f":{line}" if line > 0 else ""
        section = f"[{label}{line_label}]\n{content.strip()}\n"
        if not section.strip():
            continue
        remaining = max_chars - used
        if remaining <= 0:
            break
        if len(section) > remaining:
            parts.append(section[:remaining] + "\n...[truncated]")
            used = max_chars
            break
        parts.append(section)
        used += len(section)

    return "\n".join(parts).strip()
