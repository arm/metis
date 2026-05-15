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

_SEM_USR = "{all_functions_code}"

_COMBINED_GRAPH_SYS = (
    """\
You are analyzing a C/C++ codebase with several requested security lenses in one review.
Evaluate each requested lens independently, then merge duplicate root causes before
returning JSON. Run only the requested lenses below.

Requested lenses:
{lens_instructions}

Output examples:
{lens_examples}

Return ONLY valid JSON:
{{"findings": [{{"analysis_type": "semantic", "vulnerability_type": "missing_auth",
"severity": "high", "confidence": "high", "function_name": "gpu_ioctl_reset",
"related_function": "gpu_check_perm", "description": "...", "root_cause": "...",
"evidence": "...", "mitigation": "..."}}]}}

analysis_type is mandatory and must exactly be one of: {allowed_analysis_types}
For lifecycle findings, set function_name to the use/deref function and related_function
to the free, teardown, or lifetime-ending function when known.
For ownership findings, set function_name to the defective cleanup/caller function and
related_function to the paired function when known.
For all other findings, set function_name to the primary defective function and
related_function only when another shown function is needed to explain the bug.
Do not report style issues, hypothetical risks without a shown path/mechanism, or
duplicates already represented by the same root cause.
Return {{"findings": []}} if none found. Be conservative but thorough."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_COMBINED_GRAPH_USR = "{all_functions_code}"

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
