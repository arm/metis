# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
import re

from metis.engine.analysis.c_family_helpers import extract_code_like_symbols

REVIEW_SECURITY_QUERY_TERMS = (
    "auth",
    "authorize",
    "permission",
    "privilege",
    "token",
    "secret",
    "key",
    "password",
    "crypto",
    "sanitize",
    "validate",
    "check",
    "bound",
    "length",
    "overflow",
    "underflow",
    "memcpy",
    "strcpy",
    "malloc",
    "free",
    "sql",
    "query",
    "command",
    "exec",
    "deserialize",
    "upload",
    "path",
)

REVIEW_OBLIGATION_KEYWORDS: dict[str, tuple[str, ...]] = {
    "component purpose": (
        "purpose",
        "component",
        "module",
        "responsible",
        "responsibility",
        "enforce",
        "enforcement",
    ),
    "externally controlled inputs": (
        "input",
        "extern",
        "user",
        "request",
        "argument",
        "arg",
        "token",
        "payload",
    ),
    "callers or wrappers": (
        "caller",
        "called by",
        "call site",
        "wrapper",
        "invoked",
        "used by",
        "reference",
    ),
    "trust or privilege boundary": (
        "trust",
        "boundary",
        "privilege",
        "permission",
        "authorize",
        "auth",
        "role",
        "principal",
    ),
    "validation / sanitization / authorization checks": (
        "validate",
        "validation",
        "sanitize",
        "sanitization",
        "check",
        "guard",
        "verify",
        "bounds",
        "length",
        "authorize",
    ),
    "key unresolved gaps": (
        "gap",
        "unknown",
        "unclear",
        "unresolved",
        "missing",
        "none",
    ),
}

REVIEW_OBLIGATION_SECTION_NAMES: dict[str, str] = {
    "component purpose": "COMPONENT_PURPOSE",
    "externally controlled inputs": "INPUT_SOURCES",
    "callers or wrappers": "RELATED_CALLERS",
    "trust or privilege boundary": "TRUST_BOUNDARY",
    "validation / sanitization / authorization checks": "VALIDATION_GUARDS",
    "key unresolved gaps": "UNRESOLVED",
}

_SECTION_HEADER_RE = re.compile(r"^\[([A-Z_]+)\]\s*$", re.MULTILINE)
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_LOW_VALUE_QUERY_TOKENS = {
    "what",
    "when",
    "where",
    "which",
    "this",
    "that",
    "code",
    "docs",
    "file",
    "mode",
    "scope",
    "question",
    "security",
    "review",
    "evidence",
    "collection",
    "related",
    "current",
    "around",
    "implementation",
}


def extract_review_focus_terms(
    file_path: str,
    snippet: str,
    original_file: str = "",
    *,
    limit: int = 8,
) -> list[str]:
    lowered = " ".join(
        str(part or "") for part in (snippet, file_path, original_file)
    ).lower()
    terms: list[str] = []
    for term in REVIEW_SECURITY_QUERY_TERMS:
        if term in lowered:
            terms.append(term)
            if len(terms) >= limit:
                break
    return terms


def build_review_retrieval_query(
    *,
    file_path: str,
    relative_file: str = "",
    mode: str = "file",
    snippet: str,
    original_file: str = "",
) -> tuple[str, list[str], list[str]]:
    symbols = extract_code_like_symbols(
        file_path,
        relative_file,
        snippet,
        original_file,
        limit=12,
    )
    focus_terms = extract_review_focus_terms(file_path, snippet, original_file)
    symbol_text = ", ".join(symbols) if symbols else "<none>"
    focus_text = ", ".join(focus_terms) if focus_terms else "<none>"
    scope_text = (
        "changed code and the surrounding implementation"
        if mode == "patch"
        else "the current file and directly related callers, helpers, and guards"
    )
    query = (
        "Security review evidence collection.\n"
        f"Review scope: {scope_text}.\n"
        f"File: {file_path or '<unknown>'}\n"
        f"Mode: {mode}\n"
        f"Candidate symbols: {symbol_text}\n"
        f"Security focus terms: {focus_text}\n"
        f"Snippet:\n{snippet}\n\n"
        "Question: What related code or documentation explains the component purpose, "
        "externally controlled inputs, callers, trust boundaries, validation or sanitization "
        "responsibilities, enforcement points, and security-relevant assumptions for this code?"
    )
    return query, symbols, focus_terms


def assess_review_context_quality(
    text: str,
    *,
    file_path: str,
    symbols: list[str],
    focus_terms: list[str],
) -> tuple[bool, str]:
    normalized = str(text or "").strip()
    if not normalized:
        return False, "empty"

    lowered = normalized.lower()
    score = 0
    reasons: list[str] = []

    file_name = Path(file_path).name.lower()
    if file_name and file_name in lowered:
        score += 2
        reasons.append("file-name")

    matched_symbols = [
        symbol for symbol in symbols if symbol and symbol.lower() in lowered
    ]
    if matched_symbols:
        score += min(3, len(matched_symbols))
        reasons.append(f"symbols={len(matched_symbols)}")

    matched_focus = [term for term in focus_terms if term and term in lowered]
    if matched_focus:
        score += min(2, len(matched_focus))
        reasons.append(f"security-terms={len(matched_focus)}")

    query_tokens = build_review_quality_tokens(
        file_path=file_path,
        symbols=symbols,
        focus_terms=focus_terms,
    )
    matched_query_tokens = [token for token in query_tokens if token in lowered]
    if matched_query_tokens:
        score += min(3, len(matched_query_tokens))
        reasons.append(f"query-tokens={len(matched_query_tokens)}")

    typed_sections = parse_review_typed_sections(normalized)
    relevant_typed_sections = {
        name: content
        for name, content in typed_sections.items()
        if name in REVIEW_OBLIGATION_SECTION_NAMES.values()
    }
    if relevant_typed_sections:
        score += min(3, len(relevant_typed_sections))
        reasons.append(f"typed-sections={len(relevant_typed_sections)}")

    coverage = compute_review_obligation_coverage(
        normalized,
        symbols=symbols,
        focus_terms=focus_terms,
    )
    covered_count = sum(1 for covered in coverage.values() if covered)
    if covered_count:
        score += min(3, covered_count)
        reasons.append(f"obligations={covered_count}")

    if "[" in normalized and "]" in normalized:
        score += 1
        reasons.append("citations")

    if ":" in normalized:
        score += 1
        reasons.append("structured")

    strong_signal = (
        bool(file_name and file_name in lowered)
        or bool(matched_symbols)
        or bool(matched_query_tokens)
        or bool(relevant_typed_sections)
        or (covered_count >= 2)
    )
    verdict = score >= 2 and strong_signal
    if verdict:
        return True, ",".join(reasons) if reasons else "accepted"
    detail = ",".join(reasons) if reasons else "insufficient-match"
    return False, f"low-signal:{detail}"


def compute_review_obligation_coverage(
    text: str,
    *,
    symbols: list[str],
    focus_terms: list[str],
) -> dict[str, bool]:
    lowered = str(text or "").lower()
    typed_sections = parse_review_typed_sections(text)
    coverage: dict[str, bool] = {}
    for obligation, keywords in REVIEW_OBLIGATION_KEYWORDS.items():
        keyword_match = any(keyword in lowered for keyword in keywords)
        symbol_match = obligation == "callers or wrappers" and any(
            symbol and symbol.lower() in lowered for symbol in symbols
        )
        focus_match = obligation == "trust or privilege boundary" and any(
            term in lowered for term in focus_terms
        )
        section_name = REVIEW_OBLIGATION_SECTION_NAMES[obligation]
        section_match = bool(typed_sections.get(section_name))
        coverage[obligation] = bool(
            section_match or keyword_match or symbol_match or focus_match
        )
    return coverage


def missing_review_obligations(coverage: dict[str, bool]) -> list[str]:
    return [name for name, covered in coverage.items() if not covered]


def build_review_evidence_frame(
    *,
    query: str,
    symbols: list[str],
    focus_terms: list[str],
    baseline_quality: str,
    baseline_context: str,
    coverage: dict[str, bool],
) -> str:
    if baseline_context:
        gaps = (
            "Prefer citing baseline context first, then use tools only for unresolved "
            "obligations."
        )
    else:
        gaps = (
            "Baseline retrieval was weak or empty; use tools to resolve missing callers, "
            "guards, and trust boundaries."
        )
    missing = missing_review_obligations(coverage)
    sections = [
        "[RETRIEVAL_QUERY]",
        query.strip(),
        "",
        "[CANDIDATE_SYMBOLS]",
        ", ".join(symbols) if symbols else "<none>",
        "",
        "[SECURITY_FOCUS]",
        ", ".join(focus_terms) if focus_terms else "<none>",
        "",
        "[BASELINE_RETRIEVAL_QUALITY]",
        baseline_quality or "unknown",
        "",
        "[OBLIGATION_COVERAGE]",
        "\n".join(
            f"- {name}: {'covered' if covered else 'missing'}"
            for name, covered in coverage.items()
        ),
        "",
        "[MISSING_OBLIGATIONS]",
        "\n".join(f"- {name}" for name in missing) if missing else "- <none>",
        "",
        "[GAP_HINT]",
        gaps,
    ]
    return "\n".join(sections).strip()


def shape_review_rag_query(
    raw_query: str,
    *,
    file_path: str,
    mode: str,
    symbols: list[str],
    focus_terms: list[str],
    uncovered_obligations: list[str],
    baseline_query: str = "",
) -> str:
    normalized_query = str(raw_query or "").strip()
    if not normalized_query:
        normalized_query = (
            "What related code or docs resolve the missing security review obligations?"
        )
    symbol_text = ", ".join(symbols[:10]) if symbols else "<none>"
    focus_text = ", ".join(focus_terms[:8]) if focus_terms else "<none>"
    obligation_text = (
        ", ".join(uncovered_obligations) if uncovered_obligations else "<none>"
    )
    sections = [
        "Security review targeted retrieval.",
        f"File: {file_path or '<unknown>'}",
        f"Mode: {mode or 'file'}",
        f"Candidate symbols: {symbol_text}",
        f"Security focus terms: {focus_text}",
        f"Missing obligations: {obligation_text}",
        f"Requested lookup: {normalized_query}",
    ]
    if baseline_query:
        sections.extend(["", "[BASELINE_RETRIEVAL_QUESTION]", baseline_query.strip()])
    sections.extend(
        [
            "",
            "Return code-first evidence that helps resolve the missing obligations. "
            "Prefer callers, wrappers, guards, trust boundaries, and enforcement logic.",
        ]
    )
    return "\n".join(sections).strip()


def build_review_quality_tokens(
    *,
    file_path: str,
    symbols: list[str],
    focus_terms: list[str],
) -> list[str]:
    path_tokens = [
        token.lower()
        for token in _TOKEN_RE.findall(Path(file_path or "").name)
        if token.lower() not in _LOW_VALUE_QUERY_TOKENS
    ]
    symbol_tokens = [
        token.lower()
        for token in symbols
        if token and token.lower() not in _LOW_VALUE_QUERY_TOKENS
    ]
    focus_tokens = [
        token.lower()
        for token in focus_terms
        if token and token.lower() not in _LOW_VALUE_QUERY_TOKENS
    ]
    ordered: list[str] = []
    seen: set[str] = set()
    for token in path_tokens + symbol_tokens + focus_tokens:
        if token in seen:
            continue
        seen.add(token)
        ordered.append(token)
    return ordered


def classify_review_evidence(
    text: str,
    *,
    symbols: list[str],
    focus_terms: list[str],
) -> dict[str, list[str]]:
    buckets = {name: [] for name in REVIEW_OBLIGATION_SECTION_NAMES.values()}
    normalized = str(text or "").strip()
    if not normalized:
        return buckets

    segments = [
        segment.strip()
        for segment in re.split(r"\n\s*\n", normalized)
        if segment.strip()
    ]
    lowered_focus = [term.lower() for term in focus_terms if term]
    lowered_symbols = [symbol.lower() for symbol in symbols if symbol]

    for segment in segments:
        lowered = segment.lower()
        if any(
            keyword in lowered
            for keyword in REVIEW_OBLIGATION_KEYWORDS["component purpose"]
        ):
            buckets["COMPONENT_PURPOSE"].append(segment)
        if any(
            keyword in lowered
            for keyword in REVIEW_OBLIGATION_KEYWORDS["externally controlled inputs"]
        ):
            buckets["INPUT_SOURCES"].append(segment)
        if any(
            keyword in lowered
            for keyword in REVIEW_OBLIGATION_KEYWORDS["callers or wrappers"]
        ) or any(symbol in lowered for symbol in lowered_symbols):
            buckets["RELATED_CALLERS"].append(segment)
        if any(
            keyword in lowered
            for keyword in REVIEW_OBLIGATION_KEYWORDS["trust or privilege boundary"]
        ) or any(term in lowered for term in lowered_focus):
            buckets["TRUST_BOUNDARY"].append(segment)
        if any(
            keyword in lowered
            for keyword in REVIEW_OBLIGATION_KEYWORDS[
                "validation / sanitization / authorization checks"
            ]
        ):
            buckets["VALIDATION_GUARDS"].append(segment)
        if any(
            keyword in lowered
            for keyword in REVIEW_OBLIGATION_KEYWORDS["key unresolved gaps"]
        ):
            buckets["UNRESOLVED"].append(segment)

    for key, values in buckets.items():
        deduped: list[str] = []
        seen: set[str] = set()
        for value in values:
            compact = value.strip()
            if not compact or compact in seen:
                continue
            seen.add(compact)
            deduped.append(compact)
        buckets[key] = deduped
    return buckets


def parse_review_typed_sections(text: str) -> dict[str, str]:
    normalized = str(text or "")
    matches = list(_SECTION_HEADER_RE.finditer(normalized))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        name = match.group(1)
        start = match.end()
        end = (
            matches[index + 1].start() if index + 1 < len(matches) else len(normalized)
        )
        content = normalized[start:end].strip()
        if content:
            sections[name] = content
    return sections
