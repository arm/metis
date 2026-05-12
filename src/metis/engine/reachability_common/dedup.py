# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Root-cause deduplication for findings from multiple reachability passes."""

from __future__ import annotations
import re
from collections import defaultdict

from .utils import (
    _VTYPE_FAMILY,
    _finding_file,
    _finding_function,
    _finding_line,
    _finding_text,
    _normalise_vuln_type,
    _safe_int,
)
def _finding_signature(f):
    """
    Produce a canonical key that identifies the root cause, not the path.
    Canonical keys are intentionally not privileged here because independent
    passes often invent different keys for the same defect.
    """
    family = _dedupe_family(f)
    file = _finding_file(f)
    fn = _finding_function(f)
    line = _finding_line(f)
    line_bucket = line // 10

    return (file, fn, family, line_bucket)


_DEDUP_NOISY_CANONICAL_TOKENS = frozenset({
    "unchecked", "direct", "same_path", "same", "input",
    "user", "attacker", "unsanitized", "unsanitised",
})
_DEDUP_STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "can",
    "code", "does", "for", "from", "has", "have", "in", "into", "is",
    "it", "its", "may", "not", "of", "on", "or", "report",
    "same", "that", "the", "this", "to", "when", "where", "with",
    "without", "would",
})
_DEDUP_TOKEN_ALIASES = {
    "uncancelled": "uncanceled",
    "uncancelling": "uncanceled",
    "cancelled": "cancel",
    "canceled": "cancel",
    "cancelling": "cancel",
    "deactivation": "deactivate",
    "deactivated": "deactivate",
    "deactivates": "deactivate",
    "pathname": "path",
    "paths": "path",
    "fopen": "open",
    "opened": "open",
    "opening": "open",
    "leaks": "leak",
    "leaking": "leak",
    "pages": "page",
    "mappings": "mapping",
    "callbacks": "callback",
    "timers": "timer",
    "workers": "worker",
    "files": "file",
    "entries": "entry",
    "resources": "resource",
    "roles": "role",
    "levels": "level",
    "operations": "operation",
    "permissions": "permission",
    "authenticated": "auth",
    "authentication": "auth",
    "authorization": "auth",
    "authorized": "auth",
    "authorised": "auth",
    "unregistering": "unregister",
    "unregistered": "unregister",
    "registration": "register",
    "registered": "register",
    "registers": "register",
    "freed": "free",
    "freeing": "free",
    "released": "release",
    "releasing": "release",
    "decremented": "decrement",
    "decrements": "decrement",
    "incremented": "increment",
    "increments": "increment",
    "unsanitised": "unsanitized",
    "specifiers": "specifier",
    "formats": "format",
    "logging": "log",
    "logged": "log",
    "titles": "title",
    "strings": "string",
    "unterminated": "unterminate",
    "terminated": "terminate",
    "terminator": "terminate",
    "termination": "terminate",
    "nul": "null",
    "expired": "expire",
    "expires": "expire",
    "swept": "sweep",
    "sweeping": "sweep",
    "maintenance": "maintain",
}
_CALLBACK_TEARDOWN_TYPES = frozenset({
    "teardown_race", "callback_uaf", "deferred_uaf",
    "cleanup_symmetry", "file_ops_lifecycle_gap",
})
_CALLBACK_LIFECYCLE_TYPES = frozenset({
    "teardown_race", "callback_uaf", "deferred_uaf", "cleanup_symmetry",
    "file_ops_lifecycle_gap", "state_order", "accounting_drift",
    "use_after_free",
})
_AUTH_DEDUP_TYPES = frozenset({
    "missing_auth",
    "permission_mismatch",
    "wrong_constant",
    "auth_logic_error",
    "auth_comparison_logic_error",
    "boolean_coercion",
})
_AUTH_HELPER_DEDUP_TYPES = frozenset({
    "permission_mismatch",
    "wrong_constant",
    "auth_logic_error",
    "auth_comparison_logic_error",
    "boolean_coercion",
})
_REFCOUNT_RELEASE_TYPES = frozenset({
    "accounting_drift", "refcount_imbalance", "double_free",
    "cleanup_symmetry", "partial_cleanup", "partial_cleanup_on_error",
})
_MEMORY_BOUNDS_TYPES = frozenset({
    "buffer_overflow", "out_of_bounds", "array_index_oob",
    "array_index_size_mismatch", "missing_bounds_check",
    "integer_overflow", "integer_overflow_in_allocation",
    "integer_overflow_allocation", "array_oob",
    "wrong_struct_field", "stale_length", "field_staleness_after_mutation",
    "field_staleness",
})
_TYPE_METADATA_TYPES = frozenset({
    "type_confusion", "wrong_struct_field", "field_staleness_after_mutation",
    "field_staleness", "stale_length", "width_mismatch",
})
_FORMAT_STRING_TYPES = frozenset({
    "format_string", "info_leak",
})
_STRING_BOUNDS_TYPES = frozenset({
    "buffer_overflow", "out_of_bounds", "missing_bounds_check",
})
_SESSION_LIFETIME_TYPES = frozenset({
    "refcount_imbalance", "use_after_free", "double_free", "null_deref",
    "state_order",
})
_STATE_ACCOUNTING_TYPES = frozenset({
    "accounting_drift", "state_order", "stale_state_after_disable",
    "premature_state_transition", "use_after_free",
})
_LOCAL_METADATA_BOUNDS_TYPES = frozenset({
    "null_deref", "missing_bounds_check", "buffer_overflow",
    "type_confusion", "wrong_struct_field",
})
_CALLBACK_OBJECT_TOKENS = frozenset({
    "callback", "cb", "work", "worker", "workqueue", "timer", "watchdog",
    "flush", "cancel", "release", "reset", "poll", "ioctl", "file", "fops",
    "notify", "register", "unregister", "ctx", "context", "active",
})
_CALLBACK_LIFECYCLE_STRONG_TOKENS = frozenset({
    "callback", "cb", "work", "worker", "workqueue", "timer", "watchdog",
    "flush", "cancel", "notify", "register", "unregister", "ctx",
    "context", "active",
})
_PRIVILEGED_OP_TOKENS = frozenset({
    "reset", "firmware", "fw", "debug", "mmio", "dma", "register",
    "channel", "delete", "destroy", "load", "write", "cpu", "gpu",
    "project", "proj", "task", "create", "update", "resource", "res",
    "permission", "domain", "level", "role", "boolean",
    "auth", "owner", "session", "import", "export", "stats", "list", "add",
})
_REFCOUNT_RELEASE_TOKENS = frozenset({
    "ref", "refcount", "reference", "unref", "release", "free", "decrement",
    "increment", "count", "entry", "cleanup",
})
_BOUNDS_TOKENS = frozenset({
    "length", "len", "size", "bounds", "bound", "overflow", "underflow",
    "array", "index", "copy", "memcpy", "memset", "buffer", "payload",
})
_TYPE_METADATA_TOKENS = frozenset({
    "type", "tag", "metadata", "field", "length", "len", "raw", "payload",
    "cast", "struct", "store",
})
_FORMAT_STRING_TOKENS = frozenset({
    "format", "printf", "vprintf", "specifier", "util", "log", "title",
    "msg",
})
_STRING_BOUNDS_TOKENS = frozenset({
    "title", "strlen", "string", "terminate", "unterminate", "null",
    "buffer", "payload", "import", "task", "create", "field", "body",
})
_SESSION_LIFETIME_TOKENS = frozenset({
    "session", "fresh", "maintain", "sweep", "expire", "free", "lifetime",
    "pointer", "get", "authed", "refcount", "reference", "close",
})
_AUTH_HELPER_TOKENS = frozenset({
    "auth", "get", "level", "boolean", "resource", "permission", "role",
    "domain", "capability",
})
_STATE_ACCOUNTING_TOKENS = frozenset({
    "project", "member", "members", "count", "cache", "cached", "entry",
    "task", "delete", "remove", "clear", "stale", "project_id",
})
_LOCAL_METADATA_BOUNDS_TOKENS = frozenset({
    "identity", "full", "strlen", "memcpy", "copy", "length", "len",
    "store", "size", "tag", "cast", "data", "task", "title", "buffer",
})


def _dedupe_family(f):
    vtype = _normalise_vuln_type(getattr(f, "vulnerability_type", ""))
    return _VTYPE_FAMILY.get(vtype, vtype)


def _normalise_dedupe_token(token):
    token = _DEDUP_TOKEN_ALIASES.get(token, token)
    if token in _DEDUP_TOKEN_ALIASES:
        return _DEDUP_TOKEN_ALIASES[token]
    if len(token) > 5:
        for suffix in ("ingly", "edly", "ation", "ing", "ed"):
            if token.endswith(suffix) and len(token) - len(suffix) >= 4:
                return token[:-len(suffix)]
    return token


def _normalise_dedupe_tokens(text, *, drop_noisy=False):
    tokens = []
    for raw in re.split(r"[^a-z0-9]+", str(text or "").lower()):
        if not raw or raw in _DEDUP_STOPWORDS:
            continue
        if drop_noisy and raw in _DEDUP_NOISY_CANONICAL_TOKENS:
            continue
        token = _normalise_dedupe_token(raw)
        if not token or token in _DEDUP_STOPWORDS:
            continue
        if drop_noisy and token in _DEDUP_NOISY_CANONICAL_TOKENS:
            continue
        if len(token) < 2:
            continue
        tokens.append(token)
    return tokens


def _normalise_canonical_key(key):
    tokens = _normalise_dedupe_tokens(key, drop_noisy=True)
    return "_".join(tokens)


def _root_tokens(f):
    text = " ".join(str(part or "") for part in (
        getattr(f, "root_cause", ""),
        getattr(f, "evidence", ""),
        getattr(f, "description", ""),
    ))
    return set(_normalise_dedupe_tokens(text))


def _root_cause_token_signature(f):
    tokens = sorted(_root_tokens(f))
    if not tokens:
        return None
    return (_finding_file(f), _finding_function(f), _dedupe_family(f), tuple(tokens[:14]))


def _token_overlap_score(tokens_a, tokens_b):
    if not tokens_a or not tokens_b:
        return 0.0
    overlap = len(tokens_a & tokens_b)
    shorter = min(len(tokens_a), len(tokens_b))
    return overlap / shorter if shorter else 0.0


def _description_overlap(a: str, b: str, threshold=0.6) -> bool:
    """Normalized word-overlap check for duplicate root-cause prose."""
    wa = set(_normalise_dedupe_tokens(a))
    wb = set(_normalise_dedupe_tokens(b))
    if not wa or not wb:
        return False
    return _token_overlap_score(wa, wb) >= threshold


def _finding_info(f):
    vtype = _normalise_vuln_type(getattr(f, "vulnerability_type", ""))
    return {
        "finding": f,
        "vtype": vtype,
        "family": _VTYPE_FAMILY.get(vtype, vtype),
        "file": _finding_file(f),
        "fn": _finding_function(f),
        "line": _finding_line(f),
        "sink_file": getattr(f, "sink_file", "") or "",
        "sink_line": _safe_int(getattr(f, "sink_line", 0), 0),
        "canon": _normalise_canonical_key(getattr(f, "canonical_key", "")),
        "tokens": _root_tokens(f),
        "text": _finding_text(f),
    }


def _compatible_dedupe_family(a, b):
    types = {a["vtype"], b["vtype"]}
    if types <= _AUTH_DEDUP_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _PRIVILEGED_OP_TOKENS
        if a["fn"] == b["fn"]:
            if "missing_auth" in types and len(types) > 1:
                return bool(shared) and a["line"] and b["line"] and abs(a["line"] - b["line"]) <= 3
            return bool(shared) or (a["line"] and b["line"] and abs(a["line"] - b["line"]) <= 5)
        if not (types <= _AUTH_HELPER_DEDUP_TYPES):
            return False
        helper_shared = (a["tokens"] & b["tokens"]) & _AUTH_HELPER_TOKENS
        return (
            "auth" in helper_shared
            and "level" in helper_shared
            and bool(helper_shared & {"boolean", "resource", "permission"})
            and len(helper_shared) >= 3
        )
    if types <= _FORMAT_STRING_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _FORMAT_STRING_TOKENS
        return bool(shared & {"format", "printf", "vprintf"}) or len(shared) >= 2
    if types <= _STRING_BOUNDS_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _STRING_BOUNDS_TOKENS
        if (
            {"title", "strlen"} <= shared
            or ("title" in shared and bool(shared & {"terminate", "unterminate", "null"}))
            or len(shared) >= 4
        ):
            return True
    if types <= _SESSION_LIFETIME_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _SESSION_LIFETIME_TOKENS
        lifetime_signal = {"fresh", "maintain", "sweep", "expire", "refcount", "lifetime"}
        if "session" in shared and bool(shared & lifetime_signal) and len(shared) >= 2:
            return True
    if types <= _STATE_ACCOUNTING_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _STATE_ACCOUNTING_TOKENS
        if a["fn"] == b["fn"] and len(shared) >= 2:
            return True
    if types <= _LOCAL_METADATA_BOUNDS_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _LOCAL_METADATA_BOUNDS_TOKENS
        if a["fn"] == b["fn"] and len(shared) >= 2:
            return True
    if types <= _REFCOUNT_RELEASE_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _REFCOUNT_RELEASE_TOKENS
        return bool(shared) or a["family"] == b["family"]
    if types <= _MEMORY_BOUNDS_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _BOUNDS_TOKENS
        return bool(shared) or a["family"] == b["family"]
    if types <= _TYPE_METADATA_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _TYPE_METADATA_TOKENS
        return bool(shared) or a["family"] == b["family"]
    if a["family"] == b["family"]:
        return True
    if types <= _CALLBACK_LIFECYCLE_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _CALLBACK_LIFECYCLE_STRONG_TOKENS
        return bool(shared)
    return False


def _same_root_cause(a, b):
    if a["canon"] and a["canon"] == b["canon"]:
        return True

    if not _compatible_dedupe_family(a, b):
        return False

    if a["sink_line"] and a["sink_line"] == b["sink_line"] and a["sink_file"] == b["sink_file"]:
        return True

    same_primary = a["file"] == b["file"] and a["fn"] == b["fn"]
    same_file = a["file"] == b["file"]

    types = {a["vtype"], b["vtype"]}
    if types <= _FORMAT_STRING_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _FORMAT_STRING_TOKENS
        if ("format" in shared or "printf" in shared or "vprintf" in shared) and len(shared) >= 2:
            return True

    if types <= _STRING_BOUNDS_TYPES and same_file:
        shared = (a["tokens"] & b["tokens"]) & _STRING_BOUNDS_TOKENS
        string_signal = {"strlen", "terminate", "unterminate", "null"}
        if "title" in shared and bool(shared & string_signal) and len(shared) >= 3:
            return True
        if len(shared) >= 5 and _token_overlap_score(a["tokens"], b["tokens"]) >= 0.30:
            return True

    if types <= _SESSION_LIFETIME_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _SESSION_LIFETIME_TOKENS
        lifetime_signal = {"fresh", "maintain", "sweep", "expire", "refcount", "lifetime"}
        if "session" in shared and bool(shared & lifetime_signal) and len(shared) >= 3:
            return True

    if types <= _AUTH_DEDUP_TYPES:
        helper_shared = (a["tokens"] & b["tokens"]) & _AUTH_HELPER_TOKENS
        if (
            types <= _AUTH_HELPER_DEDUP_TYPES
            and
            "auth" in helper_shared
            and "level" in helper_shared
            and bool(helper_shared & {"boolean", "resource", "permission"})
            and _token_overlap_score(a["tokens"], b["tokens"]) >= 0.25
        ):
            return True

    if types <= _CALLBACK_LIFECYCLE_TYPES and same_file:
        shared = (a["tokens"] & b["tokens"]) & _CALLBACK_LIFECYCLE_STRONG_TOKENS
        if shared and _token_overlap_score(a["tokens"], b["tokens"]) >= 0.35:
            return True

    if not same_primary:
        return False

    if a["line"] and b["line"] and abs(a["line"] - b["line"]) <= 10:
        return True

    if _description_overlap(a["text"], b["text"], threshold=0.58):
        return True

    if _token_overlap_score(a["tokens"], b["tokens"]) >= 0.62 and len(a["tokens"] & b["tokens"]) >= 4:
        return True

    if types <= _CALLBACK_LIFECYCLE_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _CALLBACK_LIFECYCLE_STRONG_TOKENS
        if shared and (not a["line"] or not b["line"] or abs(a["line"] - b["line"]) <= 25):
            return True

    if types <= _AUTH_DEDUP_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _PRIVILEGED_OP_TOKENS
        if shared and _token_overlap_score(a["tokens"], b["tokens"]) >= 0.35:
            return True

    if types <= _REFCOUNT_RELEASE_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _REFCOUNT_RELEASE_TOKENS
        if shared and _token_overlap_score(a["tokens"], b["tokens"]) >= 0.35:
            return True

    if types <= _STATE_ACCOUNTING_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _STATE_ACCOUNTING_TOKENS
        if shared and _token_overlap_score(a["tokens"], b["tokens"]) >= 0.30:
            return True

    if types <= _MEMORY_BOUNDS_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _BOUNDS_TOKENS
        if shared and _token_overlap_score(a["tokens"], b["tokens"]) >= 0.40:
            return True

    if types <= _TYPE_METADATA_TYPES:
        shared = (a["tokens"] & b["tokens"]) & _TYPE_METADATA_TOKENS
        if shared and _token_overlap_score(a["tokens"], b["tokens"]) >= 0.40:
            return True

    return False


def _collapse_by_root_cause(findings):
    if len(findings) <= 1:
        return list(findings)

    infos = [_finding_info(f) for f in findings]
    parent = list(range(len(infos)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri

    pair_candidates = set()

    def add_pairs(indices):
        indices = list(indices)
        for i in range(len(indices)):
            for j in range(i + 1, len(indices)):
                pair_candidates.add((indices[i], indices[j]))

    by_location = defaultdict(list)
    by_canon = defaultdict(list)
    by_sink = defaultdict(list)
    by_root_sig = defaultdict(list)
    by_callback_file = defaultdict(list)
    by_auth_location = defaultdict(list)
    by_auth_helper = defaultdict(list)
    by_format_signal = defaultdict(list)
    by_string_bounds_file = defaultdict(list)
    by_session_lifetime = defaultdict(list)
    for idx, info in enumerate(infos):
        by_location[(info["file"], info["fn"])].append(idx)
        if info["canon"]:
            by_canon[info["canon"]].append(idx)
        if info["sink_line"]:
            by_sink[(info["sink_file"], info["sink_line"], info["family"])].append(idx)
        root_sig = _root_cause_token_signature(info["finding"])
        if root_sig:
            by_root_sig[root_sig].append(idx)
        if info["vtype"] in _CALLBACK_LIFECYCLE_TYPES and info["tokens"] & _CALLBACK_LIFECYCLE_STRONG_TOKENS:
            by_callback_file[info["file"]].append(idx)
        if info["vtype"] in _AUTH_DEDUP_TYPES:
            by_auth_location[(info["file"], info["fn"])].append(idx)
            if info["vtype"] in _AUTH_HELPER_DEDUP_TYPES and info["tokens"] & _AUTH_HELPER_TOKENS:
                by_auth_helper["auth_level"].append(idx)
        if info["vtype"] in _FORMAT_STRING_TYPES and info["tokens"] & _FORMAT_STRING_TOKENS:
            by_format_signal["format"].append(idx)
        if info["vtype"] in _STRING_BOUNDS_TYPES and info["tokens"] & _STRING_BOUNDS_TOKENS:
            by_string_bounds_file[info["file"]].append(idx)
        if (
            info["vtype"] in _SESSION_LIFETIME_TYPES
            and "session" in info["tokens"]
            and info["tokens"] & _SESSION_LIFETIME_TOKENS
        ):
            by_session_lifetime["session"].append(idx)

    for group in by_location.values():
        add_pairs(group)
    for group in by_canon.values():
        add_pairs(group)
    for group in by_sink.values():
        add_pairs(group)
    for group in by_root_sig.values():
        add_pairs(group)
    for group in by_callback_file.values():
        add_pairs(group)
    for group in by_auth_location.values():
        add_pairs(group)
    for group in by_auth_helper.values():
        add_pairs(group)
    for group in by_format_signal.values():
        add_pairs(group)
    for group in by_string_bounds_file.values():
        add_pairs(group)
    for group in by_session_lifetime.values():
        add_pairs(group)

    for i, j in pair_candidates:
        if _same_root_cause(infos[i], infos[j]):
            union(i, j)

    groups = defaultdict(list)
    for idx, info in enumerate(infos):
        groups[find(idx)].append(info["finding"])

    return [_pick_best(group) for group in groups.values()]


class Deduplicator:
    @staticmethod
    def deduplicate(findings, *, max_per_sink=3):
        """
        Two-stage deduplication:
        1. Group by logical root-cause signature.
           Within each group keep only the best (highest severity, shortest path).
        2. Across remaining findings, cap per (primary_function, vuln family) at max_per_sink.
        """
        if not findings: return [], 0, 0

        # Stage 1: collapse duplicate reports of the same root cause.
        stage1 = _collapse_by_root_cause(list(findings))

        # Stage 1b: catch any remaining prose-level duplicates within a location/family bucket.
        stage1b = _collapse_by_description(stage1)

        # Stage 2: cap per (sink_function, vuln_type)
        sink_groups = defaultdict(list)
        for f in stage1b:
            vtype = _normalise_vuln_type(f.vulnerability_type)
            family = _VTYPE_FAMILY.get(vtype, vtype)
            sink_groups[(f.primary_function or f.sink_function, family)].append(f)
        selected = []
        for g in sink_groups.values():
            selected.extend(_select_diverse(g, max_per_sink))

        return selected, len(findings), len(findings) - len(selected)


def _pick_best(findings):
    """Pick the single best representative from a group of duplicates."""
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    conf = {"high": 0, "medium": 1, "low": 2}
    vprio = {
        "use_after_free": 0,
        "double_free": 0,
        "double_close": 0,
        "teardown_race": 0,
        "stale_pointer_after_realloc": 0,
        "format_string": 0,
        "out_of_bounds": 0,
        "buffer_overflow": 0,
        "integer_overflow": 0,
        "integer_overflow_in_allocation": 0,
        "missing_auth": 0,
        "permission_mismatch": 0,
        "auth_comparison_logic_error": 0,
        "refcount_imbalance": 1,
        "missing_bounds_check": 1,
        "boolean_coercion": 1,
        "info_leak": 1,
        "type_confusion": 1,
        "state_order": 2,
        "null_deref": 3,
    }
    best = min(findings, key=lambda f: (
        sev.get(f.severity, 5),
        vprio.get(_normalise_vuln_type(getattr(f, "vulnerability_type", "")), 2),
        conf.get(f.confidence, 3),
        len(f.path),
        -len(f.description),  # prefer longer descriptions
    ))
    best.vulnerability_type = _normalise_vuln_type(best.vulnerability_type)
    return best


def _collapse_by_description(findings):
    """Within same primary location and family, merge highly overlapping descriptions."""
    groups = defaultdict(list)
    for f in findings:
        vtype = _normalise_vuln_type(f.vulnerability_type)
        key = (
            f.primary_file or f.sink_file or f.source_file,
            f.primary_function or f.sink_function or f.source_function,
            _VTYPE_FAMILY.get(vtype, vtype),
            _safe_int(f.primary_line or f.sink_line or f.source_line, 0) // 10,
        )
        groups[key].append(f)

    result = []
    for key, group in groups.items():
        if len(group) <= 1:
            result.extend(group)
            continue
        # greedy clustering by description overlap
        clusters = []
        for f in group:
            merged = False
            for cluster in clusters:
                if _description_overlap(_finding_text(f), _finding_text(cluster[0]), threshold=0.55):
                    cluster.append(f)
                    merged = True
                    break
            if not merged:
                clusters.append([f])
        for cluster in clusters:
            result.append(_pick_best(cluster))
    return result


def _select_diverse(findings, limit):
    if len(findings) <= limit: return list(findings)
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    fs = sorted(findings, key=lambda f: (sev.get(f.severity, 5), len(f.path)))
    sel, cov = [], set()
    for f in fs:
        if len(sel) >= limit: break
        if not sel or len(set(f.path) - cov) > 0: sel.append(f); cov.update(f.path)
    if len(sel) < limit:
        ids = {id(f) for f in sel}
        for f in fs:
            if id(f) not in ids: sel.append(f)
            if len(sel) >= limit: break
    return sel
