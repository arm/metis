# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Graph-wide supplementary audits for C/C++ reachability review."""

from __future__ import annotations
import logging
import os
import re
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.usage import submit_with_current_context
from metis.utils import parse_json_output

from .confirmer import _CANONICAL_FINDING_INSTRUCTIONS
from .models import VulnerabilityFinding
from .utils import (
    _build_file_grouped_chunks,
    _build_file_grouped_node_chunks,
    _build_globals_code,
    _canonical_fields,
    _chat_model_kwargs,
    _chunked,
    _lookup_fn,
    _normalise_vuln_type,
    _read_function_body,
)

logger = logging.getLogger("metis")
_RESOURCE_KW = frozenset(
    {
        "free",
        "malloc",
        "calloc",
        "realloc",
        "close",
        "destroy",
        "release",
        "delete",
        "munmap",
        "unref",
        "grow",
        "compact",
        "resize",
        "kfree",
        "vfree",
        "devm_kfree",
        "put",
        "get",
        "ref",
        "unref",
    }
)
_AUTH_KW = frozenset(
    {
        "auth",
        "login",
        "check",
        "verify",
        "compare",
        "validate",
        "token",
        "password",
        "permit",
        "deny",
        "match",
        "level",
        "permission",
        "capable",
        "access_ok",
    }
)
_HW_STATE_KW = frozenset(
    {
        "ready",
        "init",
        "enable",
        "disable",
        "reset",
        "power",
        "suspend",
        "resume",
        "probe",
        "remove",
        "shutdown",
        "flush",
        "drain",
        "start",
        "stop",
        "halt",
        "abort",
        "fence",
        "sync",
        "doorbell",
        "register",
        "mmio",
        "firmware",
        "fw",
        "irq",
        "interrupt",
        "handler",
        "callback",
        "work",
        "timer",
        "schedule",
        "cancel",
        "queue",
        "dequeue",
        "lock",
        "unlock",
        "mutex",
        "spinlock",
        "spin_lock",
        "spin_unlock",
    }
)
_LIFECYCLE_KW = frozenset(
    {
        "create",
        "alloc",
        "open",
        "setup",
        "teardown",
        "cleanup",
        "fini",
        "exit",
        "deinit",
        "unregister",
        "detach",
        "load",
        "unload",
        "bind",
        "unbind",
    }
)

_CLASSIC_C_SINK_RE = re.compile(
    r"\b(?:sprintf|vsprintf|strcpy|strcat|gets|scanf|sscanf|memcpy|memmove|strncpy|"
    r"snprintf|system|popen|exec(?:l|le|lp|lpe|v|ve|vp|vpe)?|fopen|open|stat|"
    r"lstat|access|printf|fprintf|vprintf|vfprintf|malloc|calloc|realloc|free|"
    r"strlen|strnlen|close|auth_get_level|store_unref|store_compact|task_serialize|"
    r"util_log|session_sweep|session_close|notify_fire)\s*\(",
    re.IGNORECASE,
)
_ERROR_UNWIND_RE = re.compile(
    r"\b(?:malloc|calloc|realloc|goto|rb_link_node|rb_erase|list_add|list_del|"
    r"hash_add|insert|register)\b|return\s+(?:NULL|-1)|ctx->regions|"
    r"\b(?:region_count|queue_count|ctx_count)\b|(?:^|_)(?:insert|register|create)(?:_|$)",
    re.IGNORECASE,
)
_COUNTER_RE = re.compile(
    r"\b(?:count|refcount|refs|gpu_mappings|alias_count|region_count|queue_count|"
    r"ctx_count|nr_pages|total|get|put|create|destroy|map|unmap|alias|shrink|grow)\b|"
    r"(?:^|_)(?:get|put|ref|unref|create|destroy|map|unmap|alias|shrink|grow)(?:_|$)|"
    r"\+\+|--|\+=|-=",
    re.IGNORECASE,
)
_ORDERING_GAP_RE = re.compile(
    r"\b(?:flush|sync|drain|fence|reset|power|pm|suspend|resume|disable|enable|"
    r"shutdown|term|mmu|dma)\b|"
    r"(?:^|_)(?:flush|sync|drain|fence|reset|power|pm|suspend|resume|disable|"
    r"enable|shutdown|term|mmu|dma)(?:_|$)",
    re.IGNORECASE,
)
_PATH_ACCESS_RE = re.compile(
    r"\b(?:fopen|open|stat|lstat|access|realpath|canonicalize|snprintf)\s*\(|"
    r"\b(?:path|full_path|file|filename|fw_name|name)\b",
    re.IGNORECASE,
)
_GLOBAL_LIFECYCLE_NAME_RE = re.compile(
    r"(?:init|term|shutdown|release|destroy|poll|flush|submit|callback|worker|"
    r"timer|watchdog|open|ioctl|unregister|cancel)",
    re.IGNORECASE,
)
_LOCK_EVENT_RE = re.compile(
    r"\b(?P<fn>pthread_mutex_lock|pthread_mutex_unlock|mutex_lock|mutex_unlock|"
    r"spin_lock(?:_irqsave|_irq)?|spin_unlock(?:_irqrestore|_irq)?)\s*"
    r"\(\s*(?P<arg>[^,\)]+)",
    re.IGNORECASE,
)
_RELATED_FILE_FUNCTION_KEYWORDS = frozenset(
    {
        "init",
        "term",
        "shutdown",
        "destroy",
        "release",
        "cancel",
        "flush",
        "create",
        "get",
        "put",
        "ref",
        "unref",
        "map",
        "unmap",
        "grow",
        "shrink",
        "alias",
        "load",
        "unload",
        "verify",
        "open",
        "poll",
        "ioctl",
        "enable",
        "disable",
        "reset",
        "schedule",
        "callback",
        "worker",
        "work",
        "timer",
        "watchdog",
    }
)


def _node_match_text(codebase_path, node, max_chars=12000):
    body = _read_function_body(codebase_path, node, max_chars)
    return f"{node.name}\n{' '.join(node.calls)}\n{body}"


def _select_nodes_by_regex(graph, codebase_path, pattern, *, max_body_chars=12000):
    nodes = []
    for node in sorted(
        graph.nodes.values(), key=lambda n: (n.file_path, n.line_number, n.name)
    ):
        if pattern.search(_node_match_text(codebase_path, node, max_body_chars)):
            nodes.append(node)
    return nodes


def _function_name_tokens(name):
    return [t for t in re.split(r"[^a-z0-9]+", str(name or "").lower()) if t]


def _related_function_score(seed_nodes, node, relation_keywords):
    name_l = str(node.name or "").lower()
    if not any(k in name_l for k in relation_keywords):
        return 0

    node_tokens = set(_function_name_tokens(node.name))
    node_stem = node_tokens - set(relation_keywords)
    score = 0
    nearest = None
    for seed in seed_nodes:
        seed_tokens = set(_function_name_tokens(seed.name))
        seed_stem = seed_tokens - set(relation_keywords)
        shared_stem = node_stem & seed_stem
        if shared_stem:
            score = max(score, 10 + len(shared_stem) * 3)
        elif seed_tokens and node_tokens and sorted(seed_tokens)[0] in node_tokens:
            score = max(score, 4)
        distance = abs(int(node.line_number or 0) - int(seed.line_number or 0))
        nearest = distance if nearest is None else min(nearest, distance)
    if score and nearest is not None and nearest <= 160:
        score += max(1, 8 - nearest // 20)
    return score


def _expand_candidates_with_related_file_functions(
    graph, candidates, relation_keywords, max_extra_per_file=8
):
    """Add a capped set of same-file lifecycle/accounting siblings for local context."""
    if not candidates:
        return []
    relation_keywords = frozenset(
        str(k).lower() for k in relation_keywords if str(k).strip()
    )
    if not relation_keywords:
        return list(candidates)

    selected = {node.unique_name: node for node in candidates}
    by_file = defaultdict(list)
    for node in candidates:
        by_file[node.file_path].append(node)

    for file_path, seed_nodes in by_file.items():
        scored = []
        for node in graph.get_file_nodes(file_path):
            if node.unique_name in selected:
                continue
            score = _related_function_score(seed_nodes, node, relation_keywords)
            if score <= 0:
                continue
            nearest = min(
                abs(int(node.line_number or 0) - int(seed.line_number or 0))
                for seed in seed_nodes
            )
            scored.append(
                (-score, nearest, int(node.line_number or 0), node.name, node)
            )
        for _, _, _, _, node in sorted(scored)[:max_extra_per_file]:
            selected[node.unique_name] = node

    return sorted(
        selected.values(), key=lambda n: (n.file_path, int(n.line_number or 0), n.name)
    )


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
"free_function": "session_close", "use_function": "store_lookup", \
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
"function_a": "proto_parse", "function_b": "dispatch", \
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
"function_name": "dispatch", "related_function": "auth_get_level", \
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


class SupplementaryAnalyzer:
    """Run targeted semantic passes over graph-selected function groups."""

    def __init__(
        self,
        llm_provider,
        audit_model,
        strong_model,
        usage_runtime,
        codebase_path,
        audit_max_tokens=8192,
        strong_max_tokens=16384,
        reasoning_effort=None,
    ):
        self._p = llm_provider
        self._am = audit_model
        self._sm = strong_model
        self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path)
        self._at = audit_max_tokens
        self._st = strong_max_tokens
        self._reasoning_effort = reasoning_effort

    def analyze(
        self, graph, *, max_workers=8, progress_callback=None, analysis_profile="full"
    ):
        full_pass_specs = [
            ("intra_audit", self._pass_intra),
            ("lifecycle_audit", self._pass_lifecycle),
            ("ownership_audit", self._pass_ownership),
            ("semantic_audit", self._pass_semantic),
            ("state_audit", self._pass_state_concurrency),
            ("targeted_state_order", self._pass_targeted_state_order),
            ("targeted_callback_lifecycle", self._pass_targeted_callback_lifecycle),
            ("targeted_refcount", self._pass_targeted_refcount),
            ("targeted_permission", self._pass_targeted_permission),
            ("targeted_toctou", self._pass_targeted_toctou),
            ("classic_c_sink", self._pass_classic_c_sinks),
            ("error_unwind", self._pass_error_unwind),
            ("counter_symmetry", self._pass_counter_symmetry),
            ("global_lifecycle", self._pass_global_lifecycle),
            ("lock_order_extraction", self._pass_lock_order),
            ("targeted_ordering_gap", self._pass_targeted_ordering_gap),
            ("targeted_path_access", self._pass_targeted_path_access),
        ]
        review_pass_names = {
            "intra_audit",
            "lifecycle_audit",
            "ownership_audit",
            "semantic_audit",
            "targeted_callback_lifecycle",
            "targeted_refcount",
            "targeted_permission",
            "classic_c_sink",
            "error_unwind",
            "counter_symmetry",
            "targeted_path_access",
        }
        profile = str(analysis_profile or "full").lower()
        pass_specs = (
            [spec for spec in full_pass_specs if spec[0] in review_pass_names]
            if profile == "review"
            else full_pass_specs
        )
        findings = []
        if not pass_specs:
            return findings
        worker_budget = max(1, int(max_workers or 1))
        pass_parallelism = max(1, min(len(pass_specs), worker_budget, 8))
        pass_workers = max(1, worker_budget // pass_parallelism)

        def _run_pass(pass_name, pass_fn):
            try:
                return pass_fn(graph, pass_workers, progress_callback)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                logger.warning("%s pass fail: %s", pass_name, exc)
                if progress_callback:
                    progress_callback(
                        {
                            "event": f"{pass_name}_error",
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )
                return []

        if pass_parallelism == 1:
            for pass_name, pass_fn in pass_specs:
                findings.extend(_run_pass(pass_name, pass_fn))
        else:
            with ThreadPoolExecutor(max_workers=pass_parallelism) as executor:
                futures = {
                    submit_with_current_context(
                        executor, _run_pass, pass_name, pass_fn
                    ): pass_name
                    for pass_name, pass_fn in pass_specs
                }
                for future in as_completed(futures):
                    findings.extend(future.result())
        if progress_callback:
            by_type = defaultdict(int)
            for f in findings:
                by_type[f.analysis_type] += 1
            progress_callback(
                {"event": "supplementary_done", **dict(by_type), "total": len(findings)}
            )
        return findings

    def _pass_intra(self, graph, max_workers, cb):
        targets = self._select_intra_targets(graph)
        if not targets:
            return []
        groups = defaultdict(list)
        for t in targets:
            groups[t.file_path].append(t)
        if cb:
            cb(
                {
                    "event": "intra_audit_start",
                    "files": len(groups),
                    "functions": len(targets),
                }
            )
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {
                submit_with_current_context(ex, self._audit_file, fp, fns): fp
                for fp, fns in groups.items()
            }
            done = 0
            for fut in as_completed(futs):
                fp = futs[fut]
                done += 1
                try:
                    results.extend(fut.result())
                except Exception as e:
                    logger.warning("Intra audit fail %s: %s", fp, e)
                if cb:
                    cb(
                        {
                            "event": "intra_audit_progress",
                            "completed": done,
                            "total": len(groups),
                            "file": fp,
                        }
                    )
        return results

    def _select_intra_targets(self, graph):
        all_kw = _RESOURCE_KW | _AUTH_KW | _HW_STATE_KW | _LIFECYCLE_KW
        seen, targets = set(), []
        for n in graph.nodes.values():
            nl = n.name.lower()
            cl = [c.lower() for c in n.calls]
            ac = nl + " " + " ".join(cl)
            if n.is_sink or n.is_source or any(k in ac for k in all_kw) or "goto" in ac:
                if n.unique_name not in seen:
                    seen.add(n.unique_name)
                    targets.append(n)
        # if we missed any functions (small codebase), include everything
        if len(targets) < len(graph.nodes) * 0.3:
            for n in graph.nodes.values():
                if n.unique_name not in seen:
                    seen.add(n.unique_name)
                    targets.append(n)
        return targets

    def _audit_file(self, file_path, functions):
        bodies = []
        for fn in functions:
            b = _read_function_body(self._cb, fn, 4096)
            if b:
                bodies.append(f"--- {fn.unique_name} (line {fn.line_number}) ---\n{b}")
        if not bodies:
            return []
        kw = _chat_model_kwargs(
            self._u, reasoning_effort=getattr(self, "_reasoning_effort", None)
        )
        chat = self._p.get_chat_model(
            model=self._am, max_tokens=self._at, temperature=0.1, **kw
        )
        prompt = ChatPromptTemplate.from_messages(
            [("system", _INTRA_SYS), ("user", _INTRA_USR)]
        )
        raw = (
            (prompt | chat | StrOutputParser())
            .invoke({"file_path": file_path, "functions_code": "\n\n".join(bodies)})
            .strip()
        )
        return self._parse_intra(raw, functions)

    def _parse_intra(self, raw, functions, analysis_type="intra_function"):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return []
        fl = parsed.get("findings")
        if not isinstance(fl, list):
            return []
        lk = {fn.name: fn for fn in functions}
        bu = {f.unique_name: f for f in functions}
        results = []
        for e in fl:
            if not isinstance(e, dict):
                continue
            fn = _lookup_fn(str(e.get("function_name") or ""), lk, bu, functions)
            if not fn:
                fn = functions[0]
            line = fn.line_number
            try:
                line = max(1, int(e.get("line", line)))
            except (TypeError, ValueError):
                pass
            primary_file, primary_function, primary_line, canonical_key = (
                _canonical_fields(
                    e,
                    default_file=fn.file_path,
                    default_function=fn.unique_name,
                    default_line=line,
                )
            )
            results.append(
                VulnerabilityFinding(
                    id=uuid.uuid4().hex[:16],
                    vulnerability_type=_normalise_vuln_type(
                        e.get("vulnerability_type") or "other"
                    ),
                    severity=str(e.get("severity") or "medium"),
                    confidence=str(e.get("confidence") or "medium"),
                    source_function=fn.unique_name,
                    source_file=fn.file_path,
                    source_line=line,
                    sink_function=fn.unique_name,
                    sink_file=fn.file_path,
                    sink_line=line,
                    path=[fn.unique_name],
                    description=str(e.get("description") or ""),
                    root_cause=str(e.get("root_cause") or ""),
                    evidence=str(e.get("evidence") or ""),
                    mitigation=str(e.get("mitigation") or ""),
                    analysis_type=analysis_type,
                    primary_file=primary_file,
                    primary_function=primary_function,
                    primary_line=primary_line,
                    canonical_key=canonical_key,
                )
            )
        return results

    # All use chunking to avoid blowing context windows.

    def _run_chunked_cross_pass(
        self,
        graph,
        sys_prompt,
        usr_template,
        usr_key,
        analysis_type,
        key_a,
        key_b,
        model,
        max_tokens,
        max_workers,
        cb,
        event_prefix,
        include_globals=False,
    ):
        fns = list(graph.nodes.values())
        if not fns:
            return []
        if cb:
            cb({"event": f"{event_prefix}_start", "functions": len(fns)})
        chunks = _build_file_grouped_chunks(
            self._cb, fns, max_total_chars=60000, per_fn_chars=3000
        )
        if not chunks:
            return []
        globals_code = _build_globals_code(graph) if include_globals else ""
        if globals_code:
            chunks = [
                f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{chunk}"
                for chunk in chunks
            ]
        results = []

        def _run_chunk(code_chunk):
            kw = _chat_model_kwargs(
                self._u, reasoning_effort=getattr(self, "_reasoning_effort", None)
            )
            chat = self._p.get_chat_model(
                model=model, max_tokens=max_tokens, temperature=0.1, **kw
            )
            prompt = ChatPromptTemplate.from_messages(
                [("system", sys_prompt), ("user", usr_template)]
            )
            raw = (
                (prompt | chat | StrOutputParser())
                .invoke({usr_key: code_chunk})
                .strip()
            )
            return raw

        if len(chunks) == 1:
            raw = _run_chunk(chunks[0])
            results = self._parse_cross(raw, fns, analysis_type, key_a, key_b)
        else:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(chunks))) as ex:
                futs = {
                    submit_with_current_context(ex, _run_chunk, chunk): i
                    for i, chunk in enumerate(chunks)
                }
                for fut in as_completed(futs):
                    try:
                        raw = fut.result()
                        results.extend(
                            self._parse_cross(raw, fns, analysis_type, key_a, key_b)
                        )
                    except Exception as e:
                        logger.warning("%s chunk fail: %s", event_prefix, e)

        if cb:
            cb({"event": f"{event_prefix}_done", "findings": len(results)})
        return results

    def _run_chunked_semantic_pass(self, graph, max_workers, cb):
        fns = list(graph.nodes.values())
        if not fns:
            return []
        if cb:
            cb({"event": "semantic_audit_start", "functions": len(fns)})
        chunks = _build_file_grouped_chunks(
            self._cb, fns, max_total_chars=60000, per_fn_chars=3000
        )
        if not chunks:
            return []
        globals_code = _build_globals_code(graph)
        if globals_code:
            chunks = [
                f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{chunk}"
                for chunk in chunks
            ]
        results = []

        def _run_chunk(code_chunk):
            kw = _chat_model_kwargs(
                self._u, reasoning_effort=getattr(self, "_reasoning_effort", None)
            )
            chat = self._p.get_chat_model(
                model=self._sm, max_tokens=self._st, temperature=0.1, **kw
            )
            prompt = ChatPromptTemplate.from_messages(
                [("system", _SEM_SYS), ("user", _SEM_USR)]
            )
            return (
                (prompt | chat | StrOutputParser())
                .invoke({"all_functions_code": code_chunk})
                .strip()
            )

        if len(chunks) == 1:
            raw = _run_chunk(chunks[0])
            results = self._parse_semantic(raw, fns)
        else:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(chunks))) as ex:
                futs = {
                    submit_with_current_context(ex, _run_chunk, chunk): i
                    for i, chunk in enumerate(chunks)
                }
                for fut in as_completed(futs):
                    try:
                        raw = fut.result()
                        results.extend(self._parse_semantic(raw, fns))
                    except Exception as e:
                        logger.warning("Semantic chunk fail: %s", e)

        if cb:
            cb({"event": "semantic_audit_done", "findings": len(results)})
        return results

    def _pass_lifecycle(self, graph, max_workers, cb):
        return self._run_chunked_cross_pass(
            graph,
            _LIFE_SYS,
            _LIFE_USR,
            "all_functions_code",
            "lifecycle",
            "free_function",
            "use_function",
            self._sm,
            self._st,
            max_workers,
            cb,
            "lifecycle_audit",
        )

    def _pass_ownership(self, graph, max_workers, cb):
        return self._run_chunked_cross_pass(
            graph,
            _OWN_SYS,
            _OWN_USR,
            "all_functions_code",
            "ownership",
            "function_a",
            "function_b",
            self._sm,
            self._st,
            max_workers,
            cb,
            "ownership_audit",
            include_globals=True,
        )

    def _pass_semantic(self, graph, max_workers, cb):
        return self._run_chunked_semantic_pass(graph, max_workers, cb)

    def _pass_state_concurrency(self, graph, max_workers, cb):
        """New pass: state ordering, lock discipline, teardown races."""
        fns = list(graph.nodes.values())
        if not fns:
            return []
        if cb:
            cb({"event": "state_audit_start", "functions": len(fns)})
        chunks = _build_file_grouped_chunks(
            self._cb, fns, max_total_chars=60000, per_fn_chars=3000
        )
        if not chunks:
            return []
        globals_code = _build_globals_code(graph)
        if globals_code:
            chunks = [
                f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{chunk}"
                for chunk in chunks
            ]
        results = []

        def _run_chunk(code_chunk):
            kw = _chat_model_kwargs(
                self._u, reasoning_effort=getattr(self, "_reasoning_effort", None)
            )
            chat = self._p.get_chat_model(
                model=self._sm, max_tokens=self._st, temperature=0.1, **kw
            )
            prompt = ChatPromptTemplate.from_messages(
                [("system", _STATE_SYS), ("user", _STATE_USR)]
            )
            return (
                (prompt | chat | StrOutputParser())
                .invoke({"all_functions_code": code_chunk})
                .strip()
            )

        if len(chunks) == 1:
            raw = _run_chunk(chunks[0])
            results = self._parse_semantic(raw, fns, analysis_type="state_concurrency")
        else:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(chunks))) as ex:
                futs = {
                    submit_with_current_context(ex, _run_chunk, chunk): i
                    for i, chunk in enumerate(chunks)
                }
                for fut in as_completed(futs):
                    try:
                        raw = fut.result()
                        results.extend(
                            self._parse_semantic(
                                raw, fns, analysis_type="state_concurrency"
                            )
                        )
                    except Exception as e:
                        logger.warning("State/concurrency chunk fail: %s", e)

        if cb:
            cb({"event": "state_audit_done", "findings": len(results)})
        return results

    def _run_targeted_pass(
        self,
        graph,
        sys_prompt,
        analysis_type,
        max_workers,
        cb,
        event_prefix,
        relation_keywords=None,
    ):
        fns = list(graph.nodes.values())
        if relation_keywords:
            fns = _expand_candidates_with_related_file_functions(
                graph, fns, relation_keywords
            )
        if not fns:
            return []
        if cb:
            cb({"event": f"{event_prefix}_start", "functions": len(fns)})
        chunks = _build_file_grouped_chunks(
            self._cb, fns, max_total_chars=60000, per_fn_chars=3000
        )
        if not chunks:
            return []
        globals_code = _build_globals_code(graph)
        if globals_code:
            chunks = [
                f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{chunk}"
                for chunk in chunks
            ]
        results = []

        def _run_chunk(code_chunk):
            kw = _chat_model_kwargs(
                self._u, reasoning_effort=getattr(self, "_reasoning_effort", None)
            )
            chat = self._p.get_chat_model(
                model=self._sm, max_tokens=self._st, temperature=0.1, **kw
            )
            prompt = ChatPromptTemplate.from_messages(
                [("system", sys_prompt), ("user", _SEM_USR)]
            )
            return (
                (prompt | chat | StrOutputParser())
                .invoke({"all_functions_code": code_chunk})
                .strip()
            )

        if len(chunks) == 1:
            results = self._parse_semantic(
                _run_chunk(chunks[0]), fns, analysis_type=analysis_type
            )
        else:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(chunks))) as ex:
                futs = {
                    submit_with_current_context(ex, _run_chunk, chunk): i
                    for i, chunk in enumerate(chunks)
                }
                for fut in as_completed(futs):
                    try:
                        results.extend(
                            self._parse_semantic(
                                fut.result(), fns, analysis_type=analysis_type
                            )
                        )
                    except Exception as e:
                        logger.warning("%s chunk fail: %s", event_prefix, e)
        if cb:
            cb({"event": f"{event_prefix}_done", "findings": len(results)})
        return results

    def _run_candidate_intra_pass(
        self, graph, pattern, sys_prompt, analysis_type, max_workers, cb, event_prefix
    ):
        candidates = _select_nodes_by_regex(graph, self._cb, pattern)
        if not candidates:
            return []
        if cb:
            cb({"event": f"{event_prefix}_start", "functions": len(candidates)})
        chunks = _build_file_grouped_node_chunks(
            self._cb, candidates, max_total_chars=50000, per_fn_chars=5000
        )
        if not chunks:
            return []
        results = []

        def _run_chunk(chunk_nodes, code_chunk):
            kw = _chat_model_kwargs(
                self._u, reasoning_effort=getattr(self, "_reasoning_effort", None)
            )
            chat = self._p.get_chat_model(
                model=self._sm, max_tokens=self._st, temperature=0.1, **kw
            )
            prompt = ChatPromptTemplate.from_messages(
                [("system", sys_prompt), ("user", _INTRA_USR)]
            )
            raw = (
                (prompt | chat | StrOutputParser())
                .invoke(
                    {
                        "file_path": "candidate functions",
                        "functions_code": code_chunk,
                    }
                )
                .strip()
            )
            return self._parse_intra(raw, chunk_nodes, analysis_type=analysis_type)

        with ThreadPoolExecutor(
            max_workers=max(1, min(max_workers, len(chunks)))
        ) as ex:
            futs = {
                submit_with_current_context(ex, _run_chunk, nodes, text): i
                for i, (nodes, text) in enumerate(chunks)
            }
            for fut in as_completed(futs):
                try:
                    results.extend(fut.result())
                except Exception as e:
                    logger.warning("%s chunk fail: %s", event_prefix, e)
        if cb:
            cb({"event": f"{event_prefix}_done", "findings": len(results)})
        return results

    def _run_candidate_semantic_pass(
        self,
        graph,
        pattern,
        sys_prompt,
        analysis_type,
        max_workers,
        cb,
        event_prefix,
        relation_keywords=None,
    ):
        candidates = _select_nodes_by_regex(graph, self._cb, pattern)
        if not candidates:
            return []
        if relation_keywords:
            candidates = _expand_candidates_with_related_file_functions(
                graph, candidates, relation_keywords
            )
        if cb:
            cb({"event": f"{event_prefix}_start", "functions": len(candidates)})
        chunks = _build_file_grouped_node_chunks(
            self._cb, candidates, max_total_chars=60000, per_fn_chars=4000
        )
        if not chunks:
            return []
        results = []

        def _run_chunk(chunk_nodes, code_chunk):
            kw = _chat_model_kwargs(
                self._u, reasoning_effort=getattr(self, "_reasoning_effort", None)
            )
            chat = self._p.get_chat_model(
                model=self._sm, max_tokens=self._st, temperature=0.1, **kw
            )
            prompt = ChatPromptTemplate.from_messages(
                [("system", sys_prompt), ("user", _SEM_USR)]
            )
            raw = (
                (prompt | chat | StrOutputParser())
                .invoke({"all_functions_code": code_chunk})
                .strip()
            )
            return self._parse_semantic(raw, chunk_nodes, analysis_type=analysis_type)

        with ThreadPoolExecutor(
            max_workers=max(1, min(max_workers, len(chunks)))
        ) as ex:
            futs = {
                submit_with_current_context(ex, _run_chunk, nodes, text): i
                for i, (nodes, text) in enumerate(chunks)
            }
            for fut in as_completed(futs):
                try:
                    results.extend(fut.result())
                except Exception as e:
                    logger.warning("%s chunk fail: %s", event_prefix, e)
        if cb:
            cb({"event": f"{event_prefix}_done", "findings": len(results)})
        return results

    def _pass_classic_c_sinks(self, graph, max_workers, cb):
        return self._run_candidate_intra_pass(
            graph,
            _CLASSIC_C_SINK_RE,
            _CLASSIC_C_SINK_SYS,
            "classic_c_sink",
            max_workers,
            cb,
            "classic_c_sink",
        )

    def _pass_error_unwind(self, graph, max_workers, cb):
        return self._run_candidate_semantic_pass(
            graph,
            _ERROR_UNWIND_RE,
            _ERROR_UNWIND_SYS,
            "error_unwind",
            max_workers,
            cb,
            "error_unwind",
            relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS,
        )

    def _pass_counter_symmetry(self, graph, max_workers, cb):
        return self._run_candidate_semantic_pass(
            graph,
            _COUNTER_RE,
            _COUNTER_SYMMETRY_SYS,
            "counter_symmetry",
            max_workers,
            cb,
            "counter_symmetry",
            relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS,
        )

    def _pass_targeted_ordering_gap(self, graph, max_workers, cb):
        return self._run_candidate_semantic_pass(
            graph,
            _ORDERING_GAP_RE,
            _TARGET_ORDERING_GAP_SYS,
            "targeted_ordering_gap",
            max_workers,
            cb,
            "targeted_ordering_gap",
            relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS,
        )

    def _pass_targeted_path_access(self, graph, max_workers, cb):
        return self._run_candidate_semantic_pass(
            graph,
            _PATH_ACCESS_RE,
            _TARGET_PATH_ACCESS_SYS,
            "targeted_path_access",
            max_workers,
            cb,
            "targeted_path_access",
        )

    def _pass_global_lifecycle(self, graph, max_workers, cb):
        globals_ = graph.get_globals()
        if not globals_:
            return []
        nodes_by_unique = {}
        for g in globals_:
            prefix = re.split(r"[_\W]+", g.name.lower())[0] if g.name else ""
            for ref in g.referenced_functions:
                for unique_name in graph.name_index.get(ref, []):
                    node = graph.get_node(unique_name)
                    if node:
                        nodes_by_unique[node.unique_name] = node
            for node in graph.get_file_nodes(g.file_path):
                name_l = node.name.lower()
                if _GLOBAL_LIFECYCLE_NAME_RE.search(name_l) or (
                    prefix and name_l.startswith(prefix)
                ):
                    nodes_by_unique[node.unique_name] = node
        nodes = _expand_candidates_with_related_file_functions(
            graph, list(nodes_by_unique.values()), _RELATED_FILE_FUNCTION_KEYWORDS
        )
        nodes = sorted(nodes, key=lambda n: (n.file_path, n.line_number, n.name))
        if not nodes:
            return []
        if cb:
            cb(
                {
                    "event": "global_lifecycle_start",
                    "globals": len(globals_),
                    "functions": len(nodes),
                }
            )
        chunks = _build_file_grouped_node_chunks(
            self._cb, nodes, max_total_chars=50000, per_fn_chars=4000
        )
        globals_code = _build_globals_code(graph, max_chars=30000)
        results = []

        def _run_chunk(chunk_nodes, code_chunk):
            code = f"== GLOBAL CONSTRUCTS ==\n{globals_code}\n\n{code_chunk}"
            kw = _chat_model_kwargs(
                self._u, reasoning_effort=getattr(self, "_reasoning_effort", None)
            )
            chat = self._p.get_chat_model(
                model=self._sm, max_tokens=self._st, temperature=0.1, **kw
            )
            prompt = ChatPromptTemplate.from_messages(
                [("system", _GLOBAL_LIFECYCLE_SYS), ("user", _SEM_USR)]
            )
            raw = (
                (prompt | chat | StrOutputParser())
                .invoke({"all_functions_code": code})
                .strip()
            )
            return self._parse_semantic(
                raw, chunk_nodes, analysis_type="global_lifecycle"
            )

        with ThreadPoolExecutor(
            max_workers=max(1, min(max_workers, len(chunks)))
        ) as ex:
            futs = {
                submit_with_current_context(ex, _run_chunk, chunk_nodes, text): i
                for i, (chunk_nodes, text) in enumerate(chunks)
            }
            for fut in as_completed(futs):
                try:
                    results.extend(fut.result())
                except Exception as e:
                    logger.warning("Global lifecycle chunk fail: %s", e)
        if cb:
            cb({"event": "global_lifecycle_done", "findings": len(results)})
        return results

    def _normalise_lock_expr(self, expr):
        expr = re.sub(r"/\*.*?\*/", "", str(expr or ""))
        expr = re.sub(r"\s+", "", expr).strip("&()")
        expr = re.sub(r"^\([^)]*\)", "", expr)
        expr = expr.replace("->", ".").strip("&()")
        if not expr:
            return ""
        if "hwaccess_lock" in expr:
            return "hwaccess_lock"
        if "scheduler_lock" in expr:
            return "scheduler_lock"
        if ".ctx.lock" in expr or expr.endswith("ctx.lock"):
            return "ctx.lock"
        if ".queue.lock" in expr or expr.endswith("queue.lock"):
            return "queue.lock"
        if ".pm.lock" in expr or expr.endswith("pm.lock"):
            return "pm.lock"
        if ".mmu.lock" in expr or expr.endswith("mmu.lock"):
            return "mmu.lock"
        if expr.endswith(".lock"):
            return ".".join(expr.split(".")[-2:])
        return expr

    def _extract_lock_conflicts(self, graph):
        edges = defaultdict(list)
        for node in sorted(
            graph.nodes.values(), key=lambda n: (n.file_path, n.line_number, n.name)
        ):
            body = _read_function_body(self._cb, node, 8000)
            if not body:
                continue
            held = []
            for match in _LOCK_EVENT_RE.finditer(body):
                lock = self._normalise_lock_expr(match.group("arg"))
                if not lock:
                    continue
                line = node.line_number + body[: match.start()].count("\n")
                fn_name = match.group("fn").lower()
                if "unlock" in fn_name:
                    if lock in held:
                        held.remove(lock)
                    continue
                for prior in held:
                    if prior != lock:
                        edges[(prior, lock)].append((node, line))
                if lock not in held:
                    held.append(lock)

        conflicts, seen = [], set()
        for (a, b), first_edges in edges.items():
            reverse_edges = edges.get((b, a))
            if not reverse_edges:
                continue
            for node_a, line_a in first_edges:
                for node_b, line_b in reverse_edges:
                    if node_a.unique_name == node_b.unique_name:
                        continue
                    key = tuple(
                        sorted((node_a.unique_name, node_b.unique_name))
                        + sorted((a, b))
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    conflicts.append((a, b, node_a, line_a, node_b, line_b))
                    if len(conflicts) >= 40:
                        return conflicts
        return conflicts

    def _pass_lock_order(self, graph, max_workers, cb):
        conflicts = self._extract_lock_conflicts(graph)
        if not conflicts:
            return []
        if cb:
            cb({"event": "lock_order_extraction_start", "conflicts": len(conflicts)})
        results = []
        for batch in _chunked(conflicts, 8):
            nodes = []
            seen = set()
            lines = ["== LOCK ORDER CANDIDATES =="]
            for i, (a, b, node_a, line_a, node_b, line_b) in enumerate(batch):
                lines.append(
                    f"Conflict {i}: {a} -> {b} in {node_a.unique_name} line {line_a}; "
                    f"{b} -> {a} in {node_b.unique_name} line {line_b}"
                )
                for node in (node_a, node_b):
                    if node.unique_name not in seen:
                        seen.add(node.unique_name)
                        nodes.append(node)
            body_chunks = _build_file_grouped_chunks(
                self._cb, nodes, max_total_chars=50000, per_fn_chars=5000
            )
            code = (
                "\n".join(lines)
                + "\n\n== RELEVANT FUNCTION BODIES ==\n"
                + "\n\n".join(body_chunks)
            )
            kw = _chat_model_kwargs(
                self._u, reasoning_effort=getattr(self, "_reasoning_effort", None)
            )
            chat = self._p.get_chat_model(
                model=self._sm, max_tokens=self._st, temperature=0.1, **kw
            )
            prompt = ChatPromptTemplate.from_messages(
                [("system", _LOCK_ORDER_SYS), ("user", _SEM_USR)]
            )
            raw = (
                (prompt | chat | StrOutputParser())
                .invoke({"all_functions_code": code})
                .strip()
            )
            results.extend(
                self._parse_semantic(raw, nodes, analysis_type="lock_order_extraction")
            )
        if cb:
            cb({"event": "lock_order_extraction_done", "findings": len(results)})
        return results

    def _pass_targeted_state_order(self, graph, max_workers, cb):
        return self._run_targeted_pass(
            graph,
            _TARGET_STATE_SYS,
            "targeted_state_order",
            max_workers,
            cb,
            "targeted_state_order",
        )

    def _pass_targeted_callback_lifecycle(self, graph, max_workers, cb):
        return self._run_targeted_pass(
            graph,
            _TARGET_CALLBACK_SYS,
            "targeted_callback_lifecycle",
            max_workers,
            cb,
            "targeted_callback_lifecycle",
            relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS,
        )

    def _pass_targeted_refcount(self, graph, max_workers, cb):
        return self._run_targeted_pass(
            graph,
            _TARGET_REFCOUNT_SYS,
            "targeted_refcount",
            max_workers,
            cb,
            "targeted_refcount",
        )

    def _pass_targeted_permission(self, graph, max_workers, cb):
        return self._run_targeted_pass(
            graph,
            _TARGET_PERMISSION_SYS,
            "targeted_permission",
            max_workers,
            cb,
            "targeted_permission",
        )

    def _pass_targeted_toctou(self, graph, max_workers, cb):
        return self._run_targeted_pass(
            graph,
            _TARGET_TOCTOU_SYS,
            "targeted_toctou",
            max_workers,
            cb,
            "targeted_toctou",
        )

    def _parse_cross(self, raw, all_fns, analysis_type, key_a, key_b):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return []
        fl = parsed.get("findings")
        if not isinstance(fl, list):
            return []
        bn = {fn.name: fn for fn in all_fns}
        bu = {fn.unique_name: fn for fn in all_fns}
        results = []
        for e in fl:
            if not isinstance(e, dict):
                continue
            fa = _lookup_fn(str(e.get(key_a) or ""), bn, bu, all_fns)
            fb = _lookup_fn(str(e.get(key_b) or ""), bn, bu, all_fns)
            if not fa or not fb:
                continue
            primary_file, primary_function, primary_line, canonical_key = (
                _canonical_fields(
                    e,
                    default_file=fb.file_path,
                    default_function=fb.unique_name,
                    default_line=fb.line_number,
                )
            )
            results.append(
                VulnerabilityFinding(
                    id=uuid.uuid4().hex[:16],
                    vulnerability_type=_normalise_vuln_type(
                        e.get("vulnerability_type") or "use_after_free"
                    ),
                    severity=str(e.get("severity") or "high"),
                    confidence=str(e.get("confidence") or "medium"),
                    source_function=fa.unique_name,
                    source_file=fa.file_path,
                    source_line=fa.line_number,
                    sink_function=fb.unique_name,
                    sink_file=fb.file_path,
                    sink_line=fb.line_number,
                    path=[fa.unique_name, fb.unique_name],
                    description=str(e.get("description") or ""),
                    root_cause=str(e.get("root_cause") or ""),
                    evidence=str(e.get("evidence") or ""),
                    mitigation=str(e.get("mitigation") or ""),
                    analysis_type=analysis_type,
                    primary_file=primary_file,
                    primary_function=primary_function,
                    primary_line=primary_line,
                    canonical_key=canonical_key,
                )
            )
        return results

    def _parse_semantic(self, raw, all_fns, analysis_type="semantic"):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return []
        fl = parsed.get("findings")
        if not isinstance(fl, list):
            return []
        bn = {fn.name: fn for fn in all_fns}
        bu = {fn.unique_name: fn for fn in all_fns}
        results = []
        for e in fl:
            if not isinstance(e, dict):
                continue
            fn = _lookup_fn(str(e.get("function_name") or ""), bn, bu, all_fns)
            rf = _lookup_fn(str(e.get("related_function") or ""), bn, bu, all_fns)
            if not fn:
                continue
            src_fn = rf or fn
            primary_file, primary_function, primary_line, canonical_key = (
                _canonical_fields(
                    e,
                    default_file=fn.file_path,
                    default_function=fn.unique_name,
                    default_line=fn.line_number,
                )
            )
            results.append(
                VulnerabilityFinding(
                    id=uuid.uuid4().hex[:16],
                    vulnerability_type=_normalise_vuln_type(
                        e.get("vulnerability_type") or "other"
                    ),
                    severity=str(e.get("severity") or "medium"),
                    confidence=str(e.get("confidence") or "medium"),
                    source_function=src_fn.unique_name,
                    source_file=src_fn.file_path,
                    source_line=src_fn.line_number,
                    sink_function=fn.unique_name,
                    sink_file=fn.file_path,
                    sink_line=fn.line_number,
                    path=(
                        [src_fn.unique_name, fn.unique_name] if rf else [fn.unique_name]
                    ),
                    description=str(e.get("description") or ""),
                    root_cause=str(e.get("root_cause") or ""),
                    evidence=str(e.get("evidence") or ""),
                    mitigation=str(e.get("mitigation") or ""),
                    analysis_type=analysis_type,
                    primary_file=primary_file,
                    primary_function=primary_function,
                    primary_line=primary_line,
                    canonical_key=canonical_key,
                )
            )
        return results
