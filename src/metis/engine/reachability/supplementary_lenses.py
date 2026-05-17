# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Supplementary reachability lens registry and prompt metadata."""

from __future__ import annotations

from dataclasses import dataclass

from .heuristic_data import _words
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
        analysis_type="classic_c_sink",
    ),
    _SupplementaryLensSpec(
        "error_unwind",
        "candidate_semantic",
        sys_prompt=_ERROR_UNWIND_SYS,
        analysis_type="error_unwind",
    ),
    _SupplementaryLensSpec(
        "counter_symmetry",
        "candidate_semantic",
        sys_prompt=_COUNTER_SYMMETRY_SYS,
        analysis_type="counter_symmetry",
    ),
    _SupplementaryLensSpec("global_lifecycle", "method", "_lens_global_lifecycle"),
    _SupplementaryLensSpec("lock_order_extraction", "method", "_lens_lock_order"),
    _SupplementaryLensSpec(
        "targeted_ordering_gap",
        "candidate_semantic",
        sys_prompt=_TARGET_ORDERING_GAP_SYS,
        analysis_type="targeted_ordering_gap",
    ),
    _SupplementaryLensSpec(
        "targeted_path_access",
        "candidate_semantic",
        sys_prompt=_TARGET_PATH_ACCESS_SYS,
        analysis_type="targeted_path_access",
    ),
)

_REVIEW_LENS_NAMES = set(
    "intra_audit lifecycle_audit ownership_audit semantic_audit "
    "targeted_callback_lifecycle targeted_refcount targeted_permission "
    "classic_c_sink error_unwind counter_symmetry targeted_path_access".split()
)

_COMBINED_GRAPH_LENS_KINDS = _words("cross semantic targeted")
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
