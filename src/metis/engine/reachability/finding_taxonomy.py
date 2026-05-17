# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability taxonomy data for reachability findings."""

from __future__ import annotations

from .heuristic_data import _mapping

_VULN_TO_CWE = _mapping(
    """
    buffer_overflow CWE-120 out_of_bounds CWE-787 use_after_free CWE-416
    double_free CWE-415 null_deref CWE-476 command_injection CWE-78
    format_string CWE-134 integer_overflow CWE-190 path_traversal CWE-22
    race_condition CWE-362 uninitialized_memory CWE-457 type_confusion CWE-843
    boolean_coercion CWE-253 wrong_constant CWE-697 wrong_field CWE-688
    stale_length CWE-131 double_close CWE-675 callback_uaf CWE-416
    stale_pointer CWE-825 refcount_imbalance CWE-911 state_order CWE-696
    lock_order CWE-667 missing_lock CWE-820 stale_after_unlock CWE-667
    accounting_drift CWE-682 toctou CWE-367 missing_auth CWE-862
    permission_mismatch CWE-863 info_leak CWE-532 teardown_race CWE-362
    width_mismatch CWE-681 partial_cleanup CWE-459 rollback_gap CWE-460
    deferred_uaf CWE-416 stale_state CWE-664 cleanup_symmetry CWE-459
    missing_bounds_check CWE-120 auth_comparison_logic_error CWE-863
    partial_cleanup_on_error CWE-459 ownership_overwrite CWE-772
    premature_state_transition CWE-696 stale_state_after_disable CWE-664
    ordering_gap CWE-696 file_ops_lifecycle_gap CWE-362
    """
)

_VTYPE_FAMILY = _mapping(
    """
    buffer_overflow memory_bounds out_of_bounds memory_bounds
    array_index_oob memory_bounds array_index_size_mismatch memory_bounds
    missing_bounds_check memory_bounds use_after_free lifetime deferred_uaf lifetime
    callback_uaf lifetime stale_pointer lifetime stale_pointer_after_realloc lifetime
    double_free double_release double_close double_release format_string format_string
    null_deref null_deref integer_overflow integer_overflow
    integer_overflow_in_allocation integer_overflow type_confusion type_confusion
    path_traversal filesystem_path toctou filesystem_race
    teardown_race teardown_lifecycle file_ops_lifecycle_gap teardown_lifecycle
    cleanup_symmetry teardown_lifecycle partial_cleanup cleanup rollback_gap cleanup
    state_order state_order premature_state_transition state_order
    ordering_gap state_order stale_state state_order stale_state_after_disable state_order
    lock_order lock_order stale_after_unlock lock_order missing_auth authorization
    authorization_bypass authorization permission_mismatch authorization
    wrong_constant authorization boolean_coercion authorization
    auth_logic_error authorization auth_comparison_logic_error authorization
    accounting_drift accounting refcount_imbalance refcount
    info_leak information_disclosure uninitialized_data_exposure information_disclosure
    partial_cleanup_on_error cleanup ownership_overwrite cleanup
    wrong_struct_field wrong_field field_staleness_after_mutation stale_metadata
    stale_length stale_metadata width_mismatch type_width
    """
)

_VULN_TYPE_ALIASES = _mapping(
    """
    use-after-free use_after_free double-free double_free null-deref null_deref
    null_dereference null_deref null_pointer_dereference null_deref
    buffer-overflow buffer_overflow stack_buffer_overflow buffer_overflow
    heap_buffer_overflow buffer_overflow command-injection command_injection
    os_command_injection command_injection format-string format_string
    path-traversal path_traversal race-condition race_condition
    integer-overflow integer_overflow integer_overflow_allocation integer_overflow_in_allocation
    integer_overflow_in_alloc integer_overflow_in_allocation
    allocation_overflow integer_overflow_in_allocation type-confusion type_confusion
    lock_inversion lock_order lock_order_inversion lock_order deadlock lock_order
    array_oob array_index_oob array_out_of_bounds array_index_oob
    array_index_size_mismatch array_index_oob state_ordering state_order
    field_staleness field_staleness_after_mutation
    stale_field field_staleness_after_mutation stale_length_field stale_length
    missing_cleanup partial_cleanup resource_leak partial_cleanup
    missing_authorization missing_auth missing_permission missing_auth
    authorization_bypass missing_auth auth_bypass missing_auth
    auth_logic auth_logic_error auth_comparison_logic auth_comparison_logic_error
    dangling_pointer use_after_free premature_publication state_order
    wrong_enum_constant wrong_constant wrong_resource_constant wrong_constant
    wrong_resource wrong_constant wrong_permission_constant wrong_constant
    resource_mismatch permission_mismatch information_leak info_leak
    information_disclosure info_leak arbitrary_file_read path_traversal
    arbitrary_file_write path_traversal unvalidated_path path_traversal
    filesystem_traversal path_traversal directory_traversal path_traversal
    file_traversal path_traversal missing_flush teardown_race
    uncanceled_work teardown_race uncancelled_work teardown_race
    callback_lifecycle teardown_race missing_cancel teardown_race
    missing_cancellation teardown_race counter_drift accounting_drift
    missing_decrement accounting_drift missing_increment accounting_drift
    accounting_mismatch accounting_drift accounting_leak accounting_drift
    missing_barrier ordering_gap missing_flush_barrier ordering_gap
    power_ordering_gap ordering_gap flush_ordering_gap ordering_gap
    operation_ordering_gap ordering_gap file_ops_lifecycle_gap file_ops_lifecycle_gap
    missing_file_flush file_ops_lifecycle_gap release_without_flush file_ops_lifecycle_gap
    """
)
