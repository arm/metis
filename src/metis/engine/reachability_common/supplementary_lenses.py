# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Supplementary reachability lens registry and static selection rules."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .supplementary_prompts import (
    _CLASSIC_C_SINK_SYS,
    _COUNTER_SYMMETRY_SYS,
    _ERROR_UNWIND_SYS,
    _TARGET_ORDERING_GAP_SYS,
    _TARGET_PATH_ACCESS_SYS,
)


@dataclass(frozen=True)
class _SupplementaryLensSpec:
    name: str
    kind: str
    method_name: str = ""
    sys_prompt: str = ""
    analysis_type: str = ""
    pattern: object = None
    relation_keywords: object = None


_RESOURCE_KW = frozenset(
    "free malloc calloc realloc close destroy release delete munmap unref grow "
    "compact resize kfree vfree devm_kfree put get ref unref".split()
)
_AUTH_KW = frozenset(
    "auth login check verify compare validate token password permit deny match "
    "level permission capable access_ok".split()
)
_HW_STATE_KW = frozenset(
    "ready init enable disable reset power suspend resume probe remove shutdown "
    "flush drain start stop halt abort fence sync register interrupt handler "
    "callback work timer schedule cancel queue dequeue lock unlock mutex spinlock "
    "spin_lock spin_unlock".split()
)
_LIFECYCLE_KW = frozenset(
    "create alloc open setup teardown cleanup fini exit deinit unregister detach "
    "load unload bind unbind".split()
)

_CLASSIC_C_SINK_RE = re.compile(
    r"\b(?:sprintf|vsprintf|strcpy|strcat|gets|scanf|sscanf|memcpy|memmove|strncpy|"
    r"snprintf|system|popen|exec(?:l|le|lp|lpe|v|ve|vp|vpe)?|fopen|open|stat|"
    r"lstat|access|printf|fprintf|vprintf|vfprintf|malloc|calloc|realloc|free|"
    r"strlen|strnlen|close)\s*\(",
    re.IGNORECASE,
)
_ERROR_UNWIND_RE = re.compile(
    r"\b(?:malloc|calloc|realloc|goto|rb_link_node|rb_erase|list_add|list_del|"
    r"hash_add|insert|register)\b|return\s+(?:NULL|-1)|"
    r"\b(?:object_count|resource_count|queue_count|ref_count)\b|"
    r"(?:^|_)(?:insert|register|create)(?:_|$)",
    re.IGNORECASE,
)
_COUNTER_RE = re.compile(
    r"\b(?:count|refcount|refs|object_count|resource_count|queue_count|"
    r"nr_pages|total|get|put|create|destroy|map|unmap|shrink|grow)\b|"
    r"(?:^|_)(?:get|put|ref|unref|create|destroy|map|unmap|shrink|grow)(?:_|$)|"
    r"\+\+|--|\+=|-=",
    re.IGNORECASE,
)
_ORDERING_GAP_RE = re.compile(
    r"\b(?:flush|sync|drain|fence|reset|power|pm|suspend|resume|disable|enable|"
    r"shutdown|term|transition|runtime)\b|"
    r"(?:^|_)(?:flush|sync|drain|fence|reset|power|pm|suspend|resume|disable|"
    r"enable|shutdown|term|transition|runtime)(?:_|$)",
    re.IGNORECASE,
)
_PATH_ACCESS_RE = re.compile(
    r"\b(?:fopen|open|stat|lstat|access|realpath|canonicalize|snprintf)\s*\(|"
    r"\b(?:path|full_path|file|filename|name)\b",
    re.IGNORECASE,
)
_GLOBAL_LIFECYCLE_NAME_RE = re.compile(
    r"(?:init|term|shutdown|release|destroy|poll|flush|submit|callback|worker|"
    r"timer|open|control|unregister|cancel)",
    re.IGNORECASE,
)
_LOCK_EVENT_RE = re.compile(
    r"\b(?P<fn>pthread_mutex_lock|pthread_mutex_unlock|mutex_lock|mutex_unlock|"
    r"spin_lock(?:_irqsave|_irq)?|spin_unlock(?:_irqrestore|_irq)?)\s*"
    r"\(\s*(?P<arg>[^,\)]+)",
    re.IGNORECASE,
)
_RELATED_FILE_FUNCTION_KEYWORDS = frozenset(
    "init term shutdown destroy release cancel flush create get put ref unref "
    "map unmap grow shrink load unload verify open poll enable disable reset "
    "schedule callback worker work timer".split()
)

_FULL_LENS_SPECS = (
    _SupplementaryLensSpec("intra_audit", "method", method_name="_lens_intra"),
    _SupplementaryLensSpec("lifecycle_audit", "cross", analysis_type="lifecycle"),
    _SupplementaryLensSpec("ownership_audit", "cross", analysis_type="ownership"),
    _SupplementaryLensSpec("semantic_audit", "semantic", analysis_type="semantic"),
    _SupplementaryLensSpec(
        "state_audit", "semantic", analysis_type="state_concurrency"
    ),
    _SupplementaryLensSpec(
        "targeted_state_order", "targeted", analysis_type="targeted_state_order"
    ),
    _SupplementaryLensSpec(
        "targeted_callback_lifecycle",
        "targeted",
        analysis_type="targeted_callback_lifecycle",
    ),
    _SupplementaryLensSpec(
        "targeted_refcount", "targeted", analysis_type="targeted_refcount"
    ),
    _SupplementaryLensSpec(
        "targeted_permission", "targeted", analysis_type="targeted_permission"
    ),
    _SupplementaryLensSpec(
        "targeted_toctou", "targeted", analysis_type="targeted_toctou"
    ),
    _SupplementaryLensSpec(
        "classic_c_sink",
        "candidate_intra",
        sys_prompt=_CLASSIC_C_SINK_SYS,
        pattern=_CLASSIC_C_SINK_RE,
        analysis_type="classic_c_sink",
    ),
    _SupplementaryLensSpec(
        "error_unwind",
        "candidate_semantic",
        sys_prompt=_ERROR_UNWIND_SYS,
        pattern=_ERROR_UNWIND_RE,
        analysis_type="error_unwind",
        relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS,
    ),
    _SupplementaryLensSpec(
        "counter_symmetry",
        "candidate_semantic",
        sys_prompt=_COUNTER_SYMMETRY_SYS,
        pattern=_COUNTER_RE,
        analysis_type="counter_symmetry",
        relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS,
    ),
    _SupplementaryLensSpec("global_lifecycle", "method", "_lens_global_lifecycle"),
    _SupplementaryLensSpec("lock_order_extraction", "method", "_lens_lock_order"),
    _SupplementaryLensSpec(
        "targeted_ordering_gap",
        "candidate_semantic",
        sys_prompt=_TARGET_ORDERING_GAP_SYS,
        pattern=_ORDERING_GAP_RE,
        analysis_type="targeted_ordering_gap",
        relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS,
    ),
    _SupplementaryLensSpec(
        "targeted_path_access",
        "candidate_semantic",
        sys_prompt=_TARGET_PATH_ACCESS_SYS,
        pattern=_PATH_ACCESS_RE,
        analysis_type="targeted_path_access",
    ),
)

_REVIEW_LENS_NAMES = set(
    "intra_audit lifecycle_audit ownership_audit semantic_audit "
    "targeted_callback_lifecycle targeted_refcount targeted_permission "
    "classic_c_sink error_unwind counter_symmetry targeted_path_access".split()
)

_COMBINED_GRAPH_LENS_KINDS = frozenset({"cross", "semantic", "targeted"})
_COMBINED_GRAPH_LENS_NOTES = {
    "lifecycle": """\
analysis_type lifecycle:
- Use-after-free: one function frees a resource and another later dereferences it.
- Dangling pointers: global/shared structures keep pointers that are not cleared when
  the pointed-to object is freed.
- Lifetime mismatch: object A stores a pointer to object B, but B can be destroyed
  while A still exists.
- Deferred callback UAF: timer/work/callback context points at an object
  that teardown frees without canceling/flushing/unregistering the callback.
- Stale pointer after realloc/grow/compact: code caches a pointer, then a later
  operation may move or invalidate the backing store.""",
    "ownership": """\
analysis_type ownership:
- Double-free/double-close across functions: callee frees on error and caller also
  frees, or caller frees unconditionally after ownership was transferred.
- Refcount imbalance: get/ref and put/unref are not matched, or helpers named get,
  put, ref, unref, acquire, release, retain, or drop are no-ops.
- Cleanup symmetry: setup/register allocates N resources but teardown releases fewer.
- Partial cleanup on error: init allocates A, B, C, then if C fails it forgets A/B.
- Rollback gap: list/rbtree/hash/register publishes an object and a later failure
  does not remove/unregister it.
- Callback registration lifecycle: callback context is an object that can be freed
  without unregistering or canceling the callback first.""",
    "semantic": """\
analysis_type semantic:
- Boolean coercion of rich returns: callers treat level/enum/count as boolean.
- Wrong enum/constant/domain: permission or resource checks use the wrong constant.
- Type confusion or void* miscast without a type tag/check.
- Wrong field or stale metadata: raw_len used as data_len, nr_pages vs size, old
  length/count retained after data mutation.
- Width mismatch/truncation: 32-bit checks guard size_t/uint64_t values.
- Array index vs size mismatch, integer overflow in allocation/copy sizes.
- Uninitialized data exposure, wrong flag semantics, accounting drift, info leaks.
- Missing auth/permission checks before privileged reset, diagnostics, raw resource
  access, filesystem, or control operations.""",
    "state_concurrency": """\
analysis_type state_concurrency:
- Premature state transition: ready/enabled/initialized flag set before validation,
  allocation, registration, dependency initialization, or permission checks.
- Ordering gap: flush/sync/drain/fence must complete before power-off, teardown, or
  reset, but the ordering is not enforced.
- Stale-after-unlock: value read under lock is used after unlock while mutable.
- Lock order inversion across functions.
- Teardown race: destroys mutex/workqueue/resource while pending work/timers/callbacks
  can still reference it.
- Missing lock on shared structure, stale software state after runtime disable.""",
    "targeted_state_order": """\
analysis_type targeted_state_order:
- Only report ready/state flag ordering bugs.
- Look for ready, loaded, active, initialized, enabled, runtime_active, powered,
  or online being set before prerequisites complete.
- Confirm an error path after the transition does not roll state back, or another
  function trusts that state to access resources, queues, shared state, or privileged
  operations.""",
    "targeted_callback_lifecycle": """\
analysis_type targeted_callback_lifecycle:
- Only report callback teardown symmetry bugs.
- timer/work/callback fn/data/context is initialized with an object pointer.
- Teardown/release/remove/shutdown/error cleanup/free does not cancel, deactivate,
  flush, unregister, or clear the callback before freeing the object or destroying
  its mutex/workqueue.
- operation tables show lifecycle asymmetry, such as release without
  a needed flush/cancel path.""",
    "targeted_refcount": """\
analysis_type targeted_refcount:
- Only report no-op reference counting helpers that callers rely on.
- Functions named like *_get, *_put, *_ref, *_unref, acquire, release, retain, or drop
  have empty/no-op bodies, only return a pointer, only cast, or only log.
- They do not update refcount/atomic/kref/state and do not free on final put.""",
    "targeted_permission": """\
analysis_type targeted_permission:
- Only report permission-domain mismatches or missing privileged checks.
- Operation-specific access checks use the wrong resource, role, or permission
  constant for the requested operation.
- Channel/message/reset/diagnostic/destructive operation checks the
  wrong resource constant.
- Numeric permission/role is treated as boolean, allowing low-privilege nonzero
  values through high-privilege checks.
- Generic boolean permission check used where a domain-specific capability is needed.
- reset, diagnostic, raw resource access, or privileged operation lacks
  permission checks.""",
    "targeted_toctou": """\
analysis_type targeted_toctou:
- Only report filesystem time-of-check/time-of-use bugs.
- stat, lstat, access, faccessat, or related path checks are followed by fopen, open,
  unlink, rename, chmod, chown, truncate, or mutation/open on the same path.
- There is no safe open-by-handle, O_NOFOLLOW/openat discipline, directory fd pinning,
  or post-open validation that closes the race.""",
}
_COMBINED_GRAPH_LENS_EXAMPLES = {
    "lifecycle": (
        '{"analysis_type":"lifecycle","vulnerability_type":"use_after_free",'
        '"function_name":"resource_lookup","related_function":"connection_close",'
        '"primary_file":"src/resource.c","primary_function":"src/resource.c::resource_lookup",'
        '"primary_line":42,"root_cause_id":"lookup_after_connection_close",'
        '"canonical_key":"src/resource.c:src/resource.c::resource_lookup:lifetime:lookup_after_connection_close"}'
    ),
    "ownership": (
        '{"analysis_type":"ownership","vulnerability_type":"double_free",'
        '"function_name":"dispatch_request","related_function":"parse_message",'
        '"primary_file":"src/dispatch.c","primary_function":"src/dispatch.c::dispatch_request",'
        '"primary_line":73,"root_cause_id":"request_error_double_free",'
        '"canonical_key":"src/dispatch.c:src/dispatch.c::dispatch_request:double_release:request_error_double_free"}'
    ),
    "semantic": (
        '{"analysis_type":"semantic","vulnerability_type":"boolean_coercion",'
        '"function_name":"dispatch_request","related_function":"get_permission_level",'
        '"primary_file":"src/dispatch.c","primary_function":"src/dispatch.c::dispatch_request",'
        '"primary_line":88,"root_cause_id":"permission_level_used_as_boolean",'
        '"canonical_key":"src/dispatch.c:src/dispatch.c::dispatch_request:authorization:permission_level_used_as_boolean"}'
    ),
    "state_concurrency": (
        '{"analysis_type":"state_concurrency","vulnerability_type":"state_order",'
        '"function_name":"component_init","related_function":"component_ready_check",'
        '"primary_file":"src/component.c","primary_function":"src/component.c::component_init",'
        '"primary_line":55,"root_cause_id":"ready_set_before_init_complete",'
        '"canonical_key":"src/component.c:src/component.c::component_init:state_order:ready_set_before_init_complete"}'
    ),
    "targeted_state_order": (
        '{"analysis_type":"targeted_state_order","vulnerability_type":"state_order",'
        '"function_name":"component_init","related_function":"submit_work",'
        '"primary_file":"src/component.c","primary_function":"src/component.c::component_init",'
        '"primary_line":101,"root_cause_id":"ready_before_initialization_complete",'
        '"canonical_key":"src/component.c:src/component.c::component_init:state_order:ready_before_initialization_complete"}'
    ),
    "targeted_callback_lifecycle": (
        '{"analysis_type":"targeted_callback_lifecycle","vulnerability_type":"teardown_race",'
        '"function_name":"component_remove","related_function":"component_timer_callback",'
        '"primary_file":"src/component.c","primary_function":"src/component.c::component_remove",'
        '"primary_line":140,"root_cause_id":"callback_not_cancelled_before_free",'
        '"canonical_key":"src/component.c:src/component.c::component_remove:teardown_lifecycle:callback_not_cancelled_before_free"}'
    ),
    "targeted_refcount": (
        '{"analysis_type":"targeted_refcount","vulnerability_type":"refcount_imbalance",'
        '"function_name":"object_get","related_function":"object_put",'
        '"primary_file":"src/object.c","primary_function":"src/object.c::object_get",'
        '"primary_line":33,"root_cause_id":"get_no_refcount_increment",'
        '"canonical_key":"src/object.c:src/object.c::object_get:refcount:get_no_refcount_increment"}'
    ),
    "targeted_permission": (
        '{"analysis_type":"targeted_permission","vulnerability_type":"permission_mismatch",'
        '"function_name":"handle_reset_request","related_function":"check_permission",'
        '"primary_file":"src/control.c","primary_function":"src/control.c::handle_reset_request",'
        '"primary_line":118,"root_cause_id":"reset_uses_wrong_permission",'
        '"canonical_key":"src/control.c:src/control.c::handle_reset_request:authorization:reset_uses_wrong_permission"}'
    ),
    "targeted_toctou": (
        '{"analysis_type":"targeted_toctou","vulnerability_type":"toctou",'
        '"function_name":"load_config_path","related_function":"",'
        '"primary_file":"src/config.c","primary_function":"src/config.c::load_config_path",'
        '"primary_line":64,"root_cause_id":"config_path_check_then_open",'
        '"canonical_key":"src/config.c:src/config.c::load_config_path:filesystem_race:config_path_check_then_open"}'
    ),
}
_COMBINED_GRAPH_ANALYSIS_TYPE_ALIASES = {
    "lifecycle_audit": "lifecycle",
    "life": "lifecycle",
    "ownership_audit": "ownership",
    "resource_ownership": "ownership",
    "semantic_audit": "semantic",
    "state": "state_concurrency",
    "state_audit": "state_concurrency",
    "concurrency": "state_concurrency",
    "callback_lifecycle": "targeted_callback_lifecycle",
    "refcount": "targeted_refcount",
    "permission": "targeted_permission",
    "permission_mismatch": "targeted_permission",
    "toctou": "targeted_toctou",
}
