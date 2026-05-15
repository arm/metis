# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Prompt constants for supplementary reachability analysis."""

from __future__ import annotations

from .confirmer import _CANONICAL_FINDING_INSTRUCTIONS

_INTRA_SYS = (
    """\
You are a C/C++ vulnerability expert. Examine each function below for bugs WITHIN the function itself.
Look for:
1. DOUBLE-FREE / DOUBLE-CLOSE: Can any path free/close the same resource twice? goto to cleanup that frees something already freed on an error path.
2. AUTH / COMPARISON LOGIC ERRORS: Is the CORRECT field used for length/comparison? Can empty input bypass a check? Is a return value (role/level/enum) incorrectly used as a boolean?
3. INTEGER OVERFLOW IN SIZE CALCULATIONS: Can (count * sizeof(T)) wrap size_t? Struct sizes are often 100-2000 bytes!
4. ARRAY INDEX OUT OF BOUNDS: arr[flags & 0x0F] with arr[4] - mask allows 0-15.
5. RESOURCE LEAKS on error paths: malloc without free on early return; open without close.
   Report resource leaks as partial_cleanup, not double_free.
6. FORMAT STRING: User/external data passed as format argument to printf/vfprintf/sprintf.
   Do NOT report fixed literal formats such as fprintf(out, "%s\\n", msg).
7. COMMAND INJECTION: system()/popen()/exec*() with string built from user input.
8. PATH TRAVERSAL: fopen/stat/access with path from user input without canonicalization.
9. TOCTOU: stat/access check followed by fopen/unlink on the same path.
10. NULL DEREFERENCE: Pointer used before its null-check, or dereferenced without checking after fallible lookup.
11. MISSING BOUNDS CHECK: memcpy/sprintf/strncpy with size from parameter without validation.
12. STATE ORDERING: Setting ready/enabled flag BEFORE prerequisite validation/initialization completes.
13. STALE METADATA: Modifying buffer content without updating associated length/size field.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "double_free", "severity": "high", "confidence": "high", \
"function_name": "handle_set", "line": 55, "description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be thorough but report each distinct bug only ONCE."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_INTRA_USR = "File: {file_path}\n\n{functions_code}"

_LIFE_SYS = (
    """\
You are analyzing a C/C++ codebase for USE-AFTER-FREE, DANGLING POINTER, and LIFETIME bugs spanning MULTIPLE functions.
Below are functions from the codebase. Analyze their INTERACTIONS:
1. USE-AFTER-FREE: Function A frees a resource, Function B later dereferences it.
2. DANGLING POINTERS: Pointers in global/shared structures not NULLed when target freed.
3. LIFETIME MISMATCH: Object A stores pointer to B, but B can be destroyed while A exists.
4. DEFERRED CALLBACK UAF: A timer/work/watchdog is registered with an object as context. \
   The object is freed or torn down without canceling/flushing the pending callback. \
   When the callback fires, it dereferences freed memory.
5. STALE POINTER AFTER REALLOC: Code caches a pointer, then calls a function that may \
   realloc/grow/compact the backing store. The cached pointer is now stale.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "use_after_free", "severity": "high", "confidence": "high", \
"free_function": "connection_close", "use_function": "resource_lookup", \
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_LIFE_USR = "{all_functions_code}"

_OWN_SYS = (
    """\
You are analyzing a C/C++ codebase for RESOURCE OWNERSHIP, CLEANUP COORDINATION, and TEARDOWN bugs.
Examine ALL functions below for:
1. DOUBLE-FREE / DOUBLE-CLOSE ACROSS FUNCTIONS: Function A frees on error, caller also frees unconditionally. \
   A callee frees a resource and returns error, but the caller frees the same resource on error.
2. REFCOUNT IMBALANCE: get/ref and put/unref are not called in matched pairs. \
   Also check: are get/put functions actually no-ops (empty body or just return)?
3. CLEANUP SYMMETRY: init/setup allocates or registers N resources, but teardown/cleanup \
   only releases N-1 (missing cancel_work, del_timer, unregister, iounmap, etc.).
4. PARTIAL CLEANUP ON ERROR: An init function allocates A, B, C in sequence. If C fails, \
   it cleans up C but forgets to clean up A or B.
5. ROLLBACK GAP: A function adds an entry to a data structure (rbtree, list, hash) then \
   fails a later step but does not remove the entry - leaving a dangling/corrupt entry.
6. CALLBACK / REGISTRATION LIFECYCLE: Register callback with object as context (work_queue, \
   timer, irq), free object without unregistering/canceling.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "double_free", "severity": "high", "confidence": "high", \
"function_a": "parse_message", "function_b": "dispatch_request", \
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_OWN_USR = "{all_functions_code}"

_SEM_SYS = (
    """\
You are analyzing a C/C++ codebase for SEMANTIC, TYPE, and DATA-FLOW correctness bugs.
Examine ALL functions below for:
1. BOOLEAN COERCION OF RICH RETURNS: Function returns level/enum/count, caller checks with if (!func()). \
   This collapses a multi-valued result into a binary test.
2. WRONG ENUM / CONSTANT: Permission check uses wrong resource type constant. \
   Example: checking GPU_WR permission when CPU_WR is needed.
3. TYPE CONFUSION / VOID* MISCAST: void* from generic store cast without checking type tag.
4. WRONG STRUCT FIELD: raw_len used where data_len needed, or nr_pages vs size confusion.
5. FIELD STALENESS AFTER MUTATION: Data sanitized/transformed but old length/count stored - callers use stale value.
6. WIDTH MISMATCH: A 32-bit variable used to check a 64-bit value, causing truncation. \
   Or: uint32_t comparison against a size_t/uint64_t parameter.
7. ARRAY INDEX vs SIZE MISMATCH: arr[flags & 0x0F] where array has fewer than 16 entries.
8. INTEGER OVERFLOW IN ALLOCATION: new_cap * sizeof(large_struct) wraps size_t.
9. UNINITIALIZED DATA EXPOSURE: malloc + partial init + memcpy entire struct to network/user.
10. WRONG FLAG SEMANTIC: Using DONT_NEED where NO_USER_FREE is intended, or similar flag confusion.
11. ACCOUNTING DRIFT: A counter (gpu_mappings, alias_count, nr_pages) is incremented on add \
    but not decremented on remove, or vice versa. Or: counter tracks one quantity but is \
    compared against a different quantity.
12. INFO LEAK: Logging/printing physical addresses, keys, tokens, or other sensitive data.
13. MISSING AUTH / PERMISSION CHECK: A privileged operation (reset, firmware load, debug access) \
    lacks any capability or permission check.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "boolean_coercion", "severity": "high", "confidence": "high", \
"function_name": "dispatch_request", "related_function": "get_permission_level", \
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be EXTREMELY thorough."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_SEM_USR = "{all_functions_code}"

_STATE_SYS = (
    """\
You are analyzing a C/C++ codebase for STATE ORDERING, CONCURRENCY, and SYNCHRONIZATION bugs.
Examine ALL functions below for:
1. PREMATURE STATE TRANSITION: A "ready", "enabled", or "initialized" flag/field is set \
   BEFORE the object is actually ready. Other code that checks the flag may observe \
   partially initialized state.
2. ORDERING GAP: An operation (flush, sync, drain, fence) must complete before another \
   (power off, teardown, reset), but the code does not enforce the ordering (missing \
   wait/flush/barrier before the dependent operation).
3. STALE-AFTER-UNLOCK: Code reads a value while holding a lock, releases the lock, \
   then uses the value. Another thread may have changed the underlying data.
4. LOCK ORDER INVERSION: Two or more locks are acquired in inconsistent orders across \
   different functions, creating deadlock potential. E.g. function A takes lock1->lock2 \
   but function B takes lock2->lock1.
5. TEARDOWN RACE: A teardown/cleanup function destroys a mutex, frees a workqueue, \
   or releases a resource while pending work/timers/callbacks may still reference it. \
   Must cancel/flush work before destroying the synchronization primitive.
6. MISSING LOCK: A shared data structure is accessed without holding the protecting lock \
   in some code paths, while other paths properly lock.
7. STALE STATE AFTER DISABLE: A hardware resource (doorbell, ring buffer, DMA channel) \
   is disabled but associated software state (cached pointers, pending flags) is not \
   cleared/reset, causing stale state if re-enabled or inspected.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "state_order", "severity": "high", "confidence": "high", \
"function_name": "device_init", "related_function": "device_ready_check", \
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be thorough."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_STATE_USR = "{all_functions_code}"

_TARGET_STATE_SYS = (
    """\
You are analyzing C/C++ GPU, firmware, and driver-style code for ready/state flag ordering bugs.
Target only this bug class:
- State flags or fields named like gpu_ready, loaded, active, initialized, enabled,
  runtime_active, gpu_powered, ready, or online are set before validation, allocation,
  registration, firmware load, hardware init, or capability checks complete.
- An error path after the state transition does not roll the state back.
- Other functions later trust that state flag to access hardware, firmware, DMA, queues,
  MMIO, or privileged operations.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "state_order", "severity": "high",
"confidence": "high", "function_name": "gpu_init", "related_function": "gpu_submit",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_TARGET_CALLBACK_SYS = (
    """\
You are analyzing C/C++ GPU, firmware, and driver-style code for callback teardown symmetry bugs.
Target only this bug class:
- timer/work/watchdog/callback fn/data/ctx is initialized with an object pointer.
- A pending, armed, active, scheduled, or enabled state is set later.
- Teardown, release, remove, shutdown, error cleanup, or destroy/free code does not
  cancel, deactivate, flush, unregister, or clear the callback before freeing the
  object or destroying its mutex/workqueue.
- file_operations or ops tables show lifecycle asymmetry, such as .release without
  a needed .flush/cancel path.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "teardown_race", "severity": "high",
"confidence": "high", "function_name": "gpu_remove", "related_function": "gpu_watchdog_fn",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_TARGET_REFCOUNT_SYS = (
    """\
You are analyzing C/C++ code for no-op reference counting helpers.
Target only this bug class:
- Functions named like *_get, *_put, *_ref, *_unref, acquire, release, retain, or drop
  have empty/no-op bodies, only return a pointer, only cast, or only log.
- They do not update a refcount/atomic/kref/state value and do not free on final put.
- Callers rely on those helpers for lifetime safety.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "refcount_imbalance", "severity": "high",
"confidence": "high", "function_name": "gpu_ctx_get", "related_function": "gpu_ctx_put",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_TARGET_PERMISSION_SYS = (
    """\
You are analyzing C/C++ GPU, firmware, and driver-style code for permission-domain mismatches.
Target only these bug classes:
- A privileged CPU operation checks GPU_WR or a GPU-only permission when CPU_WR is needed.
- A channel, message, firmware, reset, debug, sysfs, ioctl, or destructive operation
  checks a wrong resource constant such as RES_MSG before channel deletion.
- A function returns a numeric permission level or role and callers treat it as a boolean,
  allowing low-privilege nonzero values to pass high-privilege checks.
- A caller checks the wrong resource/domain constant for the operation being performed,
  such as checking task permission before creating/deleting a project.
- A privileged operation uses a generic boolean permission check where a domain-specific
  capability/permission check is required.
- reset, firmware load, debug, MMIO, DMA, or register access lacks capability or
  permission checks entirely.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "permission_mismatch", "severity": "high",
"confidence": "high", "function_name": "gpu_ioctl_reset", "related_function": "gpu_check_perm",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_TARGET_TOCTOU_SYS = (
    """\
You are analyzing C/C++ code for filesystem time-of-check/time-of-use bugs.
Target only this bug class:
- stat, lstat, access, faccessat, or similar path checks are followed by fopen, open,
  unlink, rename, chmod, chown, truncate, or another mutating/opening operation on
  the same or clearly related path variable.
- There is no safe open-by-handle, O_NOFOLLOW/openat discipline, directory fd pinning,
  or post-open validation that closes the race.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "toctou", "severity": "medium",
"confidence": "high", "function_name": "load_firmware_path", "related_function": "",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_CLASSIC_C_SINK_SYS = (
    """\
You are analyzing selected C/C++ functions that contain classic dangerous APIs.
Only report concrete bugs in the shown functions:
1. Unbounded sprintf/vsprintf/strcpy/strcat into fixed-size or caller-provided buffers.
2. memcpy/memmove/strncpy where the copy size may exceed destination capacity.
3. Integer overflow in allocation or copy size calculations.
4. Format string bugs ONLY when attacker-controlled data is the actual format parameter.
   Do NOT report fprintf(out, "%s\\n", msg), printf("%s", msg), or other fixed-literal
   formats as format-string vulnerabilities.
5. Command injection through system/popen/exec* with attacker-controlled command strings.
6. Path traversal/arbitrary file access when caller-controlled paths reach fopen/open/stat/access
   without canonicalization and base-directory restriction.
7. TOCTOU when stat/access/lstat is followed by open/fopen/unlink/etc. on the same path.
8. NULL dereference after failed allocation/lookup and out-of-bounds indexing.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "buffer_overflow", "severity": "high",
"confidence": "high", "function_name": "gpu_debug_dump_context", "line": 123,
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative and report each root cause once."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_ERROR_UNWIND_SYS = (
    """\
You are analyzing selected C/C++ functions for error-unwind, cleanup, and rollback bugs.
Focus only on:
- Partial cleanup: a loop allocates multiple objects and a later failure leaks earlier objects.
- Ownership overwrite: object fields such as region->pages are overwritten without releasing old storage.
- Rollback gap: rb_link_node/list_add/hash_add/insert/register publishes an object, then later
  validation or registration fails without rb_erase/list_del/hash removal/unregister.
- No-op rollback helper: cleanup calls a helper like rb_erase/list_del/unregister, but the
  helper body shown is empty or ineffective.
- Object publication before full initialization succeeds.
- Do not report borrowed pointer fields being set to NULL as leaks unless this function
  actually owns the pointed-to memory.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "rollback_gap", "severity": "high",
"confidence": "high", "function_name": "gpu_region_create", "related_function": "rb_erase",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative and do not report style-only cleanup issues."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_COUNTER_SYMMETRY_SYS = (
    """\
You are analyzing selected C/C++ functions for counter, refcount, and accounting symmetry bugs.
Compare add/remove, create/destroy, map/unmap, alias_create/alias_destroy, get/put,
grow/shrink, and allocation/free pairs.
Report only concrete mismatches:
- gpu_mappings++ on map but no decrement on unmap.
- alias_count checked but never incremented on alias creation, or not decremented on destroy.
- region/page/queue/context counts incremented but not decremented.
- Delta computed after overwriting the old value.
- No-op get/put/ref/unref helpers that callers rely on for lifetime or accounting.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "accounting_drift", "severity": "medium",
"confidence": "high", "function_name": "gpu_region_create_alias",
"related_function": "gpu_region_destroy_alias",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_GLOBAL_LIFECYCLE_SYS = (
    """\
You are analyzing global C/C++ callback and file-operations tables plus referenced functions.
Focus on:
- struct file_operations / fops tables, ops tables, timer/work/watchdog callback tables.
- .open, .release, .flush, .poll, .ioctl lifecycle expectations.
- init/term/register/unregister/cancel/flush symmetry.
- .release and .poll/.ioctl without .flush when fork/dup/shared-fd lifecycle can keep
  callbacks or references alive beyond release.
- callback fn/data initialized with object context, but teardown does not cancel/flush
  before free/destroy/mutex_destroy.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "teardown_race", "severity": "high",
"confidence": "high", "function_name": "gpu_file_release", "related_function": "gpu_file_poll",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative and report only actionable lifecycle gaps."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_LOCK_ORDER_SYS = (
    """\
You are analyzing deterministic lock acquisition sequences extracted from C/C++ functions.
Confirm only real lock-order inversions:
- Function A acquires lock A then lock B while Function B can acquire lock B then lock A.
- The locks protect shared state and the functions can run concurrently.
- Ignore sequences where one lock is released before the other is acquired or where the
  ordering is impossible due to clear call/lifecycle constraints.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "lock_order", "severity": "medium",
"confidence": "high", "function_name": "gpu_sched_submit", "related_function": "gpu_ctx_destroy",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_TARGET_ORDERING_GAP_SYS = (
    """\
You are analyzing C/C++ driver-like code for operation ordering gaps.
Focus only on:
- flush/sync/drain/fence/reset/power transition ordering bugs.
- Power state changed while mutating MMU/DMA/register/shared state.
- Power off/on published during MMU mutation.
- Missing wait/flush/barrier before dependent operation.
- Missing PM/MMU lock coordination around power transitions.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "ordering_gap", "severity": "high",
"confidence": "high", "function_name": "gpu_mmu_insert_pages",
"related_function": "gpu_power_off",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_TARGET_PATH_ACCESS_SYS = (
    """\
You are analyzing selected C/C++ functions for path traversal and filesystem TOCTOU.
Target only:
- Caller/user-controlled path used directly in fopen/open/stat/access.
- No canonicalization and no restriction to a base directory.
- /lib/firmware/%s with unchecked fw_name allowing ../ traversal.
- Direct full_path opened with no validation.
- stat/access/lstat followed by fopen/open on the same path.
Prefer vulnerability_type path_traversal or toctou. Do not classify as missing_auth
unless the real root cause is authorization rather than filesystem path validation.
Return ONLY valid JSON:
{{"findings": [{{"vulnerability_type": "path_traversal", "severity": "high",
"confidence": "high", "function_name": "gpu_fw_load_custom", "related_function": "",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}
Return {{"findings": []}} if none found. Be conservative."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)
