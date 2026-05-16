# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Finding normalization and review-field helpers."""
from __future__ import annotations


import os
import re
import uuid

from .models import VulnerabilityFinding


def _lookup_fn(name, fn_by_name, fn_by_unique, all_fns):
    if not name:
        return None
    if name in fn_by_unique:
        return fn_by_unique[name]
    if name in fn_by_name:
        return fn_by_name[name]
    for fn in all_fns:
        if name in fn.name or name in fn.unique_name:
            return fn
    return None


def _severity_title(value, default="Medium"):
    text = str(value or "").strip().lower()
    if not text:
        return default
    return text[:1].upper() + text[1:]


def _confidence_score(value, default=0.75):
    """Normalize reachability confidence labels into the legacy numeric schema."""

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, min(1.0, round(float(value), 2)))

    text = str(value or "").strip().lower()
    if not text:
        return default
    try:
        return max(0.0, min(1.0, round(float(text), 2)))
    except ValueError:
        pass

    scores = {
        "very high": 0.99,
        "high": 0.95,
        "medium": 0.75,
        "moderate": 0.75,
        "low": 0.55,
        "very low": 0.35,
        "informational": 0.5,
        "info": 0.5,
    }
    return scores.get(text, default)


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _path_key(path):
    return os.path.normpath(str(path or "")).replace("\\", "/").lstrip("./")


def _same_file_ref(a, b, base_path=None):
    if not a or not b:
        return False
    ak, bk = _path_key(a), _path_key(b)
    if ak == bk:
        return True
    if base_path and os.path.isabs(str(a)):
        try:
            ak = _path_key(os.path.relpath(str(a), base_path))
        except ValueError:
            pass
    if base_path and os.path.isabs(str(b)):
        try:
            bk = _path_key(os.path.relpath(str(b), base_path))
        except ValueError:
            pass
    return ak == bk


_CANONICAL_LINE_BUCKET_SIZE = 5


def _canonical_fields(
    entry, *, default_file, default_function, default_line, vulnerability_type="other"
):
    primary_file = str(entry.get("primary_file") or "").strip() or default_file or ""
    primary_function = (
        str(entry.get("primary_function") or "").strip() or default_function or ""
    )
    primary_line = _safe_int(entry.get("primary_line"), default_line or 0)
    if primary_line <= 0:
        primary_line = default_line or 0
    canonical_key = _canonical_key_from_parts(
        primary_file,
        primary_function,
        primary_line,
        vulnerability_type,
        _entry_root_cause_token(entry),
    )
    return primary_file, primary_function, primary_line, canonical_key


def _finding_from_llm_entry(
    entry,
    *,
    source_function,
    source_file,
    source_line,
    sink_function,
    sink_file,
    sink_line,
    path,
    analysis_type,
    default_file=None,
    default_function=None,
    default_line=None,
    default_vulnerability_type="other",
    default_severity="medium",
):
    vulnerability_type = _normalise_vuln_type(
        entry.get("vulnerability_type") or default_vulnerability_type
    )
    primary_file, primary_function, primary_line, canonical_key = _canonical_fields(
        entry,
        default_file=sink_file if default_file is None else default_file,
        default_function=(
            sink_function if default_function is None else default_function
        ),
        default_line=sink_line if default_line is None else default_line,
        vulnerability_type=vulnerability_type,
    )
    return VulnerabilityFinding(
        id=uuid.uuid4().hex[:16],
        vulnerability_type=vulnerability_type,
        severity=str(entry.get("severity") or default_severity),
        confidence=str(entry.get("confidence") or "medium"),
        source_function=source_function,
        source_file=source_file,
        source_line=source_line,
        sink_function=sink_function,
        sink_file=sink_file,
        sink_line=sink_line,
        path=list(path),
        description=str(entry.get("description") or ""),
        root_cause=str(entry.get("root_cause") or ""),
        evidence=str(entry.get("evidence") or ""),
        mitigation=str(entry.get("mitigation") or ""),
        analysis_type=analysis_type,
        primary_file=primary_file,
        primary_function=primary_function,
        primary_line=primary_line,
        canonical_key=canonical_key,
    )


def _canonical_finding_key(finding):
    return _canonical_key_from_parts(
        _finding_file(finding),
        _finding_function(finding),
        _finding_line(finding),
        getattr(finding, "vulnerability_type", ""),
        _canonical_root_token(getattr(finding, "canonical_key", "")),
    )


def _entry_root_cause_token(entry):
    for key in ("root_cause_id", "root_cause_token", "root_cause_key"):
        token = _canonical_root_token(entry.get(key))
        if token:
            return token
    return _canonical_root_token(entry.get("canonical_key"))


def _canonical_key_from_parts(
    primary_file, primary_function, primary_line, vulnerability_type, root_cause_token
):
    file_key = _canonical_path(primary_file)
    function_key = _canonical_function(primary_function)
    if not file_key or not function_key:
        return ""
    vtype = _normalise_vuln_type(vulnerability_type)
    family = _VTYPE_FAMILY.get(vtype, vtype)
    root_token = root_cause_token or f"line_{_line_bucket(primary_line)}"
    return f"{file_key}:{function_key}:{family}:{root_token}"


def _canonical_path(path):
    return _path_key(path).lower()


def _canonical_function(function_name):
    return re.sub(r"\s+", "", str(function_name or "").strip()).replace("\\", "/")


def _canonical_root_token(value):
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if ":" in text:
        text = text.rsplit(":", 1)[-1]
    tokens = re.findall(r"[a-z0-9]+", text)
    return "_".join(tokens[:8])


def _line_bucket(line):
    line = max(0, _safe_int(line, 0))
    if line <= 0:
        return 0
    return (line - 1) // _CANONICAL_LINE_BUCKET_SIZE


_VULN_TO_CWE = {
    "buffer_overflow": "CWE-120",
    "out_of_bounds": "CWE-787",
    "use_after_free": "CWE-416",
    "double_free": "CWE-415",
    "null_deref": "CWE-476",
    "command_injection": "CWE-78",
    "format_string": "CWE-134",
    "integer_overflow": "CWE-190",
    "path_traversal": "CWE-22",
    "race_condition": "CWE-362",
    "uninitialized_memory": "CWE-457",
    "type_confusion": "CWE-843",
    "boolean_coercion": "CWE-253",
    "wrong_constant": "CWE-697",
    "wrong_field": "CWE-688",
    "stale_length": "CWE-131",
    "double_close": "CWE-675",
    "callback_uaf": "CWE-416",
    "stale_pointer": "CWE-825",
    "refcount_imbalance": "CWE-911",
    # lifecycle, state, and concurrency findings
    "state_order": "CWE-696",
    "lock_order": "CWE-667",
    "missing_lock": "CWE-820",
    "stale_after_unlock": "CWE-667",
    "accounting_drift": "CWE-682",
    "toctou": "CWE-367",
    "missing_auth": "CWE-862",
    "permission_mismatch": "CWE-863",
    "info_leak": "CWE-532",
    "teardown_race": "CWE-362",
    "width_mismatch": "CWE-681",
    "partial_cleanup": "CWE-459",
    "rollback_gap": "CWE-460",
    "deferred_uaf": "CWE-416",
    "stale_state": "CWE-664",
    "cleanup_symmetry": "CWE-459",
    "missing_bounds_check": "CWE-120",
    "auth_comparison_logic_error": "CWE-863",
    "partial_cleanup_on_error": "CWE-459",
    "ownership_overwrite": "CWE-772",
    "premature_state_transition": "CWE-696",
    "stale_state_after_disable": "CWE-664",
    "ordering_gap": "CWE-696",
    "file_ops_lifecycle_gap": "CWE-362",
}


_VTYPE_FAMILY = {
    "buffer_overflow": "memory_bounds",
    "out_of_bounds": "memory_bounds",
    "array_index_oob": "memory_bounds",
    "array_index_size_mismatch": "memory_bounds",
    "missing_bounds_check": "memory_bounds",
    "use_after_free": "lifetime",
    "deferred_uaf": "lifetime",
    "callback_uaf": "lifetime",
    "stale_pointer": "lifetime",
    "stale_pointer_after_realloc": "lifetime",
    "double_free": "double_release",
    "double_close": "double_release",
    "format_string": "format_string",
    "null_deref": "null_deref",
    "integer_overflow": "integer_overflow",
    "integer_overflow_in_allocation": "integer_overflow",
    "type_confusion": "type_confusion",
    "path_traversal": "filesystem_path",
    "toctou": "filesystem_race",
    "teardown_race": "teardown_lifecycle",
    "file_ops_lifecycle_gap": "teardown_lifecycle",
    "cleanup_symmetry": "teardown_lifecycle",
    "partial_cleanup": "cleanup",
    "rollback_gap": "cleanup",
    "state_order": "state_order",
    "premature_state_transition": "state_order",
    "ordering_gap": "state_order",
    "stale_state": "state_order",
    "stale_state_after_disable": "state_order",
    "lock_order": "lock_order",
    "stale_after_unlock": "lock_order",
    "missing_auth": "authorization",
    "authorization_bypass": "authorization",
    "permission_mismatch": "authorization",
    "wrong_constant": "authorization",
    "boolean_coercion": "authorization",
    "auth_logic_error": "authorization",
    "auth_comparison_logic_error": "authorization",
    "accounting_drift": "accounting",
    "refcount_imbalance": "refcount",
    "info_leak": "information_disclosure",
    "uninitialized_data_exposure": "information_disclosure",
    "partial_cleanup_on_error": "cleanup",
    "ownership_overwrite": "cleanup",
    "wrong_struct_field": "wrong_field",
    "field_staleness_after_mutation": "stale_metadata",
    "stale_length": "stale_metadata",
    "width_mismatch": "type_width",
}


_VULN_TYPE_ALIASES = {
    "use-after-free": "use_after_free",
    "double-free": "double_free",
    "null-deref": "null_deref",
    "null_dereference": "null_deref",
    "null_pointer_dereference": "null_deref",
    "buffer-overflow": "buffer_overflow",
    "stack_buffer_overflow": "buffer_overflow",
    "heap_buffer_overflow": "buffer_overflow",
    "command-injection": "command_injection",
    "os_command_injection": "command_injection",
    "format-string": "format_string",
    "path-traversal": "path_traversal",
    "race-condition": "race_condition",
    "integer-overflow": "integer_overflow",
    "integer_overflow_allocation": "integer_overflow_in_allocation",
    "integer_overflow_in_alloc": "integer_overflow_in_allocation",
    "allocation_overflow": "integer_overflow_in_allocation",
    "type-confusion": "type_confusion",
    "lock_inversion": "lock_order",
    "lock_order_inversion": "lock_order",
    "deadlock": "lock_order",
    "array_oob": "array_index_oob",
    "array_out_of_bounds": "array_index_oob",
    "array_index_size_mismatch": "array_index_oob",
    "state_ordering": "state_order",
    "field_staleness": "field_staleness_after_mutation",
    "stale_field": "field_staleness_after_mutation",
    "stale_length_field": "stale_length",
    "missing_cleanup": "partial_cleanup",
    "resource_leak": "partial_cleanup",
    "missing_authorization": "missing_auth",
    "missing_permission": "missing_auth",
    "authorization_bypass": "missing_auth",
    "auth_bypass": "missing_auth",
    "auth_logic": "auth_logic_error",
    "auth_comparison_logic": "auth_comparison_logic_error",
    "dangling_pointer": "use_after_free",
    "premature_publication": "state_order",
    "wrong_enum_constant": "wrong_constant",
    "wrong_resource_constant": "wrong_constant",
    "wrong_resource": "wrong_constant",
    "wrong_permission_constant": "wrong_constant",
    "resource_mismatch": "permission_mismatch",
    "information_leak": "info_leak",
    "information_disclosure": "info_leak",
    "arbitrary_file_read": "path_traversal",
    "arbitrary_file_write": "path_traversal",
    "unvalidated_path": "path_traversal",
    "filesystem_traversal": "path_traversal",
    "directory_traversal": "path_traversal",
    "file_traversal": "path_traversal",
    "missing_flush": "teardown_race",
    "uncanceled_work": "teardown_race",
    "uncancelled_work": "teardown_race",
    "callback_lifecycle": "teardown_race",
    "missing_cancel": "teardown_race",
    "missing_cancellation": "teardown_race",
    "counter_drift": "accounting_drift",
    "missing_decrement": "accounting_drift",
    "missing_increment": "accounting_drift",
    "accounting_mismatch": "accounting_drift",
    "accounting_leak": "accounting_drift",
    "missing_barrier": "ordering_gap",
    "missing_flush_barrier": "ordering_gap",
    "power_ordering_gap": "ordering_gap",
    "flush_ordering_gap": "ordering_gap",
    "operation_ordering_gap": "ordering_gap",
    "file_ops_lifecycle_gap": "file_ops_lifecycle_gap",
    "missing_file_flush": "file_ops_lifecycle_gap",
    "release_without_flush": "file_ops_lifecycle_gap",
}


def _normalise_vuln_type(raw):
    t = str(raw or "other").strip().lower().replace("-", "_").replace(" ", "_")
    return _VULN_TYPE_ALIASES.get(t, t)


def _mitigation_text(finding, vulnerability_type: str | None = None) -> str:
    explicit = str(getattr(finding, "mitigation", "") or "").strip()
    if explicit:
        return explicit

    vtype = _normalise_vuln_type(
        vulnerability_type or getattr(finding, "vulnerability_type", "")
    )
    label = _VTYPE_FAMILY.get(vtype, vtype).replace("_", " ")
    return (
        f"Address the {label} issue by adding the missing validation, ordering, "
        "ownership, or cleanup guard before the reachable operation executes."
    )


def _finding_text(f):
    return " ".join(
        str(part or "")
        for part in (
            getattr(f, "description", ""),
            getattr(f, "root_cause", ""),
            getattr(f, "evidence", ""),
            getattr(f, "canonical_key", ""),
        )
    )


def _finding_file(f):
    return (
        getattr(f, "primary_file", "")
        or getattr(f, "sink_file", "")
        or getattr(f, "source_file", "")
        or ""
    )


def _finding_function(f):
    return (
        getattr(f, "primary_function", "")
        or getattr(f, "sink_function", "")
        or getattr(f, "source_function", "")
        or ""
    )


def _finding_line(f):
    return _safe_int(
        getattr(f, "primary_line", 0)
        or getattr(f, "sink_line", 0)
        or getattr(f, "source_line", 0),
        0,
    )
