# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from .models import ALLOWED_VULNERABILITY_TYPES

VTYPE_FAMILY = dict(
    item.rsplit(":", 1)
    for group in (
        "array_index_oob:memory_bounds|array_index_size_mismatch:memory_bounds|array_oob:memory_bounds",
        "auth_comparison_logic_error:authorization|auth_logic_error:authorization|authorization_bypass:authorization",
        "buffer_overflow:memory_bounds|callback_uaf:lifetime|cleanup_symmetry:cleanup",
        "out_of_bounds:memory_bounds|missing_bounds_check:memory_bounds|missing_validation:input_validation",
        "integer_overflow:integer_overflow|integer_overflow_in_allocation:integer_overflow",
        "null_dereference:null_dereference|null_deref:null_dereference|type_confusion:type_confusion",
        "use_after_free:lifetime|use_after_release:lifetime|deferred_uaf:lifetime",
        "stale_pointer:lifetime|stale_pointer_after_realloc:lifetime|lifecycle_asymmetry:lifetime",
        "double_free:double_release|double_close:double_release",
        "partial_cleanup:cleanup|partial_cleanup_on_error:cleanup|rollback_gap:cleanup|ownership_overwrite:cleanup",
        "counter_symmetry:accounting|accounting_drift:accounting|refcount_mismatch:refcount|refcount_imbalance:refcount",
        "state_ordering:state_order|state_order:state_order|premature_state_transition:state_order",
        "ordering_gap:state_order|stale_state:state_order|stale_state_after_disable:state_order",
        "race_condition:concurrency|teardown_race:teardown_lifecycle|file_ops_lifecycle_gap:teardown_lifecycle",
        "lock_order:lock_order|lock_inversion:lock_order|stale_after_unlock:lock_order|missing_lock:lock_order",
        "path_traversal:filesystem_path|toctou:filesystem_race",
        "missing_auth:authorization|permission_mismatch:authorization|wrong_constant:authorization",
        "wrong_resource_constant:authorization|boolean_coercion:authorization",
        "information_leak:information_disclosure|info_leak:information_disclosure",
        "uninitialized_data_exposure:information_disclosure|uninitialized_memory:information_disclosure",
        "stale_metadata:stale_metadata|field_staleness_after_mutation:stale_metadata|stale_length:stale_metadata",
        "width_mismatch:type_width|format_string:format_string|command_injection:command_injection|other:other",
    )
    for item in group.split("|")
)


def vulnerability_family(vulnerability_type: str) -> str:
    normalized = normalize_vulnerability_type(vulnerability_type)
    return VTYPE_FAMILY.get(normalized, normalized)


def normalize_vulnerability_type(raw: str) -> str:
    text = str(raw or "other").strip().lower().replace("-", "_").replace(" ", "_")
    text = "_".join(part for part in text.split("_") if part)
    if text in ALLOWED_VULNERABILITY_TYPES:
        return text
    return text or "other"
