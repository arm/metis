# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Prompt constants for supplementary reachability analysis."""

from __future__ import annotations

from .confirmer import _CANONICAL_FINDING_INSTRUCTIONS
from .models import ALLOWED_VULNERABILITY_TYPES
from .prompt_guidance import TRIAGE_NOISE_FILTER_GUIDANCE

_ALLOWED_VULNERABILITY_TYPES_TEXT = ", ".join(ALLOWED_VULNERABILITY_TYPES)


_STRUCTURED_FINDING_INSTRUCTIONS = f"""\
Use the structured findings schema supplied by the caller.
Populate only real values from the shown code. Do not invent files, functions, or lines.
vulnerability_type must exactly be one of: {_ALLOWED_VULNERABILITY_TYPES_TEXT}.
Use out_of_bounds for all OOB read/write/index variants, partial_cleanup for
error-unwind/rollback/resource-leak variants, and use_after_free for dangling
use-after-release lifetime variants unless a narrower allowed type fits better.
confidence must be exactly one of: high, medium, low.
{TRIAGE_NOISE_FILTER_GUIDANCE}
Return an empty findings list when the evidence does not prove a vulnerability.
"""


def _finding_prompt(body, response_guidance):
    return (
        body
        + _STRUCTURED_FINDING_INSTRUCTIONS
        + response_guidance
        + _CANONICAL_FINDING_INSTRUCTIONS
    )


_INTRA_SYS = _finding_prompt(
    """\
You are a C/C++ vulnerability expert. Examine each function below for bugs WITHIN the function itself.
Look for:
1. DOUBLE-FREE / DOUBLE-CLOSE: Can any path release the same resource twice?
2. AUTH / COMPARISON LOGIC ERRORS: Is the correct field or domain used for length,
   permission, role, enum, or status checks? Can empty input bypass a check?
3. INTEGER OVERFLOW IN SIZE CALCULATIONS: Can unchecked arithmetic wrap allocation,
   copy, or indexing sizes?
4. ARRAY INDEX OUT OF BOUNDS: Can a derived or masked index exceed the array bounds?
5. RESOURCE LEAKS on error paths: Is an owned allocation, handle, or mapping lost
   on early return or cleanup failure?
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
""",
    """\
Return no findings if none are proven. Be thorough but report each distinct bug only ONCE.""",
)

_INTRA_USR = "File: {file_path}\n\n{functions_code}"

_COMBINED_GRAPH_SYS = _finding_prompt(
    """\
Review the provided C/C++ code for the requested security analysis types only.
Evaluate each requested type independently and report one finding per distinct
root cause.

Requested analysis:
{lens_instructions}

""",
    """\
analysis_type must exactly be one of: {allowed_analysis_types}
Use function_name for the primary defective function and related_function only when
another shown function is needed to explain the bug. Prefer precise file/function/line
evidence and ignore style-only or unsupported issues. Return no findings if none are proven.""",
)

_COMBINED_GRAPH_USR = "{all_functions_code}"

_CLASSIC_C_SINK_SYS = _finding_prompt(
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
""",
    """\
analysis_type must be classic_c_sink. Return no findings if none are proven.
Be conservative and report each root cause once.""",
)

_ERROR_UNWIND_SYS = _finding_prompt(
    """\
You are analyzing selected C/C++ functions for error-unwind, cleanup, and rollback bugs.
Focus only on:
- Partial cleanup: a loop allocates multiple objects and a later failure leaks earlier objects.
- Ownership overwrite: object fields are overwritten without releasing old storage.
- Rollback gap: rb_link_node/list_add/hash_add/insert/register publishes an object, then later
  validation or registration fails without rb_erase/list_del/hash removal/unregister.
- No-op rollback helper: cleanup calls a helper like rb_erase/list_del/unregister, but the
  helper body shown is empty or ineffective.
- Object publication before full initialization succeeds.
- Do not report borrowed pointer fields being set to NULL as leaks unless this function
  actually owns the pointed-to memory.
""",
    """\
analysis_type must be error_unwind. Return no findings if none are proven.
Be conservative and do not report style-only cleanup issues.""",
)

_COUNTER_SYMMETRY_SYS = _finding_prompt(
    """\
You are analyzing selected C/C++ functions for counter, refcount, and accounting symmetry bugs.
Compare add/remove, create/destroy, map/unmap, get/put,
grow/shrink, and allocation/free pairs.
Report only concrete mismatches:
- active_mappings++ on map but no decrement on unmap.
- object_count checked but never incremented on creation, or not decremented on destroy.
- resource/page/queue/context counts incremented but not decremented.
- Delta computed after overwriting the old value.
- No-op get/put/ref/unref helpers that callers rely on for lifetime or accounting.
""",
    """\
analysis_type must be counter_symmetry. Return no findings if none are proven.
Be conservative.""",
)

_TARGET_PATH_ACCESS_SYS = _finding_prompt(
    """\
You are analyzing selected C/C++ functions for path traversal and filesystem TOCTOU.
Target only:
- Caller/user-controlled path used directly in fopen/open/stat/access.
- No canonicalization and no restriction to a base directory.
- Base-directory path built from unchecked filename allowing ../ traversal.
- Direct full_path opened with no validation.
- stat/access/lstat followed by fopen/open on the same path.
Prefer vulnerability_type path_traversal or toctou. Do not classify as missing_auth
unless the real root cause is authorization rather than filesystem path validation.
""",
    """\
analysis_type must be targeted_path_access. Return no findings if none are proven.
Be conservative.""",
)
