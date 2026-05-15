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
from dataclasses import dataclass

from metis.usage import submit_with_current_context
from metis.utils import parse_json_output

from .llm_runner import invoke_reachability_prompt
from .models import VulnerabilityFinding
from .supplementary_prompts import (
    _CLASSIC_C_SINK_SYS,
    _COMBINED_GRAPH_SYS,
    _COMBINED_GRAPH_USR,
    _COUNTER_SYMMETRY_SYS,
    _ERROR_UNWIND_SYS,
    _GLOBAL_LIFECYCLE_SYS,
    _INTRA_SYS,
    _INTRA_USR,
    _LOCK_ORDER_SYS,
    _SEM_USR,
    _TARGET_ORDERING_GAP_SYS,
    _TARGET_PATH_ACCESS_SYS,
)
from .finding_normalization import (
    _canonical_fields,
    _lookup_fn,
    _normalise_vuln_type,
)
from .domain_hints import format_domain_hints_for_prompt, normalize_domain_hints
from .graph_utils import _chunked
from .source_context import (
    _build_file_grouped_chunks,
    _build_file_grouped_node_chunks,
    _build_globals_code,
    _read_function_body,
)

logger = logging.getLogger("metis")


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
        "register",
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
        "load",
        "unload",
        "verify",
        "open",
        "poll",
        "enable",
        "disable",
        "reset",
        "schedule",
        "callback",
        "worker",
        "work",
        "timer",
    }
)

_FULL_LENS_SPECS = (
    _SupplementaryLensSpec("intra_audit", "method", method_name="_lens_intra"),
    _SupplementaryLensSpec(
        "lifecycle_audit",
        "cross",
        analysis_type="lifecycle",
    ),
    _SupplementaryLensSpec(
        "ownership_audit",
        "cross",
        analysis_type="ownership",
    ),
    _SupplementaryLensSpec(
        "semantic_audit",
        "semantic",
        analysis_type="semantic",
    ),
    _SupplementaryLensSpec(
        "state_audit",
        "semantic",
        analysis_type="state_concurrency",
    ),
    _SupplementaryLensSpec(
        "targeted_state_order",
        "targeted",
        analysis_type="targeted_state_order",
    ),
    _SupplementaryLensSpec(
        "targeted_callback_lifecycle",
        "targeted",
        analysis_type="targeted_callback_lifecycle",
    ),
    _SupplementaryLensSpec(
        "targeted_refcount",
        "targeted",
        analysis_type="targeted_refcount",
    ),
    _SupplementaryLensSpec(
        "targeted_permission",
        "targeted",
        analysis_type="targeted_permission",
    ),
    _SupplementaryLensSpec(
        "targeted_toctou",
        "targeted",
        analysis_type="targeted_toctou",
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
    _SupplementaryLensSpec(
        "global_lifecycle", "method", method_name="_lens_global_lifecycle"
    ),
    _SupplementaryLensSpec(
        "lock_order_extraction", "method", method_name="_lens_lock_order"
    ),
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

_REVIEW_LENS_NAMES = {
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


def _node_match_text(codebase_path, node, max_chars=12000):
    body = _read_function_body(codebase_path, node, max_chars)
    return f"{node.name}\n{' '.join(node.calls)}\n{body}"


def _select_nodes_by_regex(
    graph, codebase_path, pattern, *, max_body_chars=12000, extra_keywords=()
):
    nodes = []
    keywords = tuple(str(k).lower() for k in extra_keywords if str(k).strip())
    for node in sorted(
        graph.nodes.values(), key=lambda n: (n.file_path, n.line_number, n.name)
    ):
        text = _node_match_text(codebase_path, node, max_body_chars)
        if pattern.search(text) or (
            keywords and any(keyword in text.lower() for keyword in keywords)
        ):
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


class SupplementaryAnalyzer:
    """Run targeted semantic lenses over graph-selected function groups."""

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
        domain_hints=None,
        domain_profiles=None,
    ):
        self._p = llm_provider
        self._am = audit_model
        self._sm = strong_model
        self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path)
        self._at = audit_max_tokens
        self._st = strong_max_tokens
        self._reasoning_effort = reasoning_effort
        self._domain_hints = normalize_domain_hints(domain_hints, domain_profiles)
        self._domain_keywords = self._domain_hints["keywords"]
        self._domain_prompt_hints = format_domain_hints_for_prompt(self._domain_hints)

    def _with_domain_hints(self, prompt):
        if not self._domain_prompt_hints:
            return prompt
        return f"{prompt}\n\n{self._domain_prompt_hints}"

    def analyze(
        self, graph, *, max_workers=8, progress_callback=None, analysis_profile="full"
    ):
        profile = str(analysis_profile or "full").lower()
        lens_specs = (
            [spec for spec in _FULL_LENS_SPECS if spec.name in _REVIEW_LENS_NAMES]
            if profile == "review"
            else list(_FULL_LENS_SPECS)
        )
        findings = []
        if not lens_specs:
            return findings
        combined_specs = [
            spec for spec in lens_specs if spec.kind in _COMBINED_GRAPH_LENS_KINDS
        ]
        lens_jobs = [
            spec for spec in lens_specs if spec.kind not in _COMBINED_GRAPH_LENS_KINDS
        ]
        if combined_specs:
            lens_jobs.insert(0, tuple(combined_specs))
        worker_budget = max(1, int(max_workers or 1))
        lens_parallelism = max(1, min(len(lens_jobs), worker_budget, 8))
        lens_workers = max(1, worker_budget // lens_parallelism)

        def _job_name(job):
            return "combined_graph_lenses" if isinstance(job, tuple) else job.name

        def _run_lens(job):
            try:
                if isinstance(job, tuple):
                    return self._run_combined_graph_lenses(
                        job, graph, lens_workers, progress_callback
                    )
                return self._run_lens_spec(job, graph, lens_workers, progress_callback)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                name = _job_name(job)
                logger.warning("%s lens fail: %s", name, exc)
                if progress_callback:
                    progress_callback(
                        {
                            "event": f"{name}_error",
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )
                return []

        if lens_parallelism == 1:
            for job in lens_jobs:
                findings.extend(_run_lens(job))
        else:
            with ThreadPoolExecutor(max_workers=lens_parallelism) as executor:
                futures = {
                    submit_with_current_context(executor, _run_lens, job): _job_name(
                        job
                    )
                    for job in lens_jobs
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

    def _run_combined_graph_lenses(self, specs, graph, max_workers, cb):
        analysis_types = [spec.analysis_type for spec in specs]
        fns = list(graph.nodes.values())
        if not fns:
            return []
        if cb:
            cb(
                {
                    "event": "combined_graph_lenses_start",
                    "functions": len(fns),
                    "lenses": [spec.name for spec in specs],
                }
            )
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

        allowed = ", ".join(analysis_types)
        lens_instructions = "\n".join(
            _COMBINED_GRAPH_LENS_NOTES.get(analysis_type, analysis_type)
            for analysis_type in analysis_types
        )
        if self._domain_prompt_hints:
            lens_instructions = f"{lens_instructions}\n\n{self._domain_prompt_hints}"
        lens_examples = "\n".join(
            f"- {_COMBINED_GRAPH_LENS_EXAMPLES[analysis_type]}"
            for analysis_type in analysis_types
            if analysis_type in _COMBINED_GRAPH_LENS_EXAMPLES
        )
        results = []

        def _run_chunk(code_chunk):
            raw = invoke_reachability_prompt(
                self._p,
                self._u,
                model=self._sm,
                max_tokens=self._st,
                system_prompt=_COMBINED_GRAPH_SYS,
                user_prompt=_COMBINED_GRAPH_USR,
                variables={
                    "all_functions_code": code_chunk,
                    "allowed_analysis_types": allowed,
                    "lens_instructions": lens_instructions,
                    "lens_examples": lens_examples,
                },
                reasoning_effort=getattr(self, "_reasoning_effort", None),
            )
            return self._parse_combined(raw, fns, frozenset(analysis_types))

        if len(chunks) == 1:
            results = _run_chunk(chunks[0])
        else:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(chunks))) as ex:
                futs = {
                    submit_with_current_context(ex, _run_chunk, chunk): i
                    for i, chunk in enumerate(chunks)
                }
                for fut in as_completed(futs):
                    try:
                        results.extend(fut.result())
                    except Exception as e:
                        logger.warning("Combined graph lens chunk fail: %s", e)
        if cb:
            cb({"event": "combined_graph_lenses_done", "findings": len(results)})
        return results

    def _run_lens_spec(self, spec, graph, max_workers, cb):
        if spec.kind == "method":
            return getattr(self, spec.method_name)(graph, max_workers, cb)
        if spec.kind == "candidate_intra":
            return self._run_candidate_intra_lens(
                graph,
                spec.pattern,
                spec.sys_prompt,
                spec.analysis_type,
                max_workers,
                cb,
                spec.name,
            )
        if spec.kind == "candidate_semantic":
            return self._run_candidate_semantic_lens(
                graph,
                spec.pattern,
                spec.sys_prompt,
                spec.analysis_type,
                max_workers,
                cb,
                spec.name,
                relation_keywords=spec.relation_keywords,
            )
        raise ValueError(f"unknown supplementary lens kind: {spec.kind}")

    def _lens_intra(self, graph, max_workers, cb):
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
        all_kw = all_kw | set(self._domain_keywords)
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
        raw = invoke_reachability_prompt(
            self._p,
            self._u,
            model=self._am,
            max_tokens=self._at,
            system_prompt=self._with_domain_hints(_INTRA_SYS),
            user_prompt=_INTRA_USR,
            variables={"file_path": file_path, "functions_code": "\n\n".join(bodies)},
            reasoning_effort=getattr(self, "_reasoning_effort", None),
        )
        return self._parse_intra(raw, functions)

    def _finding_from_entry(
        self,
        entry,
        *,
        source_fn,
        source_line,
        sink_fn,
        sink_line,
        path,
        analysis_type,
        default_vulnerability_type="other",
        default_severity="medium",
    ):
        vulnerability_type = _normalise_vuln_type(
            entry.get("vulnerability_type") or default_vulnerability_type
        )
        primary_file, primary_function, primary_line, canonical_key = _canonical_fields(
            entry,
            default_file=sink_fn.file_path,
            default_function=sink_fn.unique_name,
            default_line=sink_line,
            vulnerability_type=vulnerability_type,
        )
        return VulnerabilityFinding(
            id=uuid.uuid4().hex[:16],
            vulnerability_type=vulnerability_type,
            severity=str(entry.get("severity") or default_severity),
            confidence=str(entry.get("confidence") or "medium"),
            source_function=source_fn.unique_name,
            source_file=source_fn.file_path,
            source_line=source_line,
            sink_function=sink_fn.unique_name,
            sink_file=sink_fn.file_path,
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
            results.append(
                self._finding_from_entry(
                    e,
                    source_fn=fn,
                    source_line=line,
                    sink_fn=fn,
                    sink_line=line,
                    path=[fn.unique_name],
                    analysis_type=analysis_type,
                )
            )
        return results

    def _run_candidate_intra_lens(
        self, graph, pattern, sys_prompt, analysis_type, max_workers, cb, event_prefix
    ):
        candidates = _select_nodes_by_regex(
            graph, self._cb, pattern, extra_keywords=self._domain_keywords
        )
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
            raw = invoke_reachability_prompt(
                self._p,
                self._u,
                model=self._sm,
                max_tokens=self._st,
                system_prompt=self._with_domain_hints(sys_prompt),
                user_prompt=_INTRA_USR,
                variables={
                    "file_path": "candidate functions",
                    "functions_code": code_chunk,
                },
                reasoning_effort=getattr(self, "_reasoning_effort", None),
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

    def _run_candidate_semantic_lens(
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
        candidates = _select_nodes_by_regex(
            graph, self._cb, pattern, extra_keywords=self._domain_keywords
        )
        if not candidates:
            return []
        if relation_keywords:
            relation_keywords = frozenset(relation_keywords) | set(
                self._domain_keywords
            )
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
            raw = invoke_reachability_prompt(
                self._p,
                self._u,
                model=self._sm,
                max_tokens=self._st,
                system_prompt=self._with_domain_hints(sys_prompt),
                user_prompt=_SEM_USR,
                variables={"all_functions_code": code_chunk},
                reasoning_effort=getattr(self, "_reasoning_effort", None),
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

    def _lens_global_lifecycle(self, graph, max_workers, cb):
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
            raw = invoke_reachability_prompt(
                self._p,
                self._u,
                model=self._sm,
                max_tokens=self._st,
                system_prompt=self._with_domain_hints(_GLOBAL_LIFECYCLE_SYS),
                user_prompt=_SEM_USR,
                variables={"all_functions_code": code},
                reasoning_effort=getattr(self, "_reasoning_effort", None),
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
        if ".queue.lock" in expr or expr.endswith("queue.lock"):
            return "queue.lock"
        if ".pm.lock" in expr or expr.endswith("pm.lock"):
            return "pm.lock"
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

    def _lens_lock_order(self, graph, max_workers, cb):
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
            raw = invoke_reachability_prompt(
                self._p,
                self._u,
                model=self._sm,
                max_tokens=self._st,
                system_prompt=self._with_domain_hints(_LOCK_ORDER_SYS),
                user_prompt=_SEM_USR,
                variables={"all_functions_code": code},
                reasoning_effort=getattr(self, "_reasoning_effort", None),
            )
            results.extend(
                self._parse_semantic(raw, nodes, analysis_type="lock_order_extraction")
            )
        if cb:
            cb({"event": "lock_order_extraction_done", "findings": len(results)})
        return results

    def _normalise_combined_analysis_type(self, value, allowed_analysis_types):
        raw = str(value or "").strip().lower().replace("-", "_")
        if raw in allowed_analysis_types:
            return raw
        alias = _COMBINED_GRAPH_ANALYSIS_TYPE_ALIASES.get(raw)
        if alias in allowed_analysis_types:
            return alias
        return ""

    def _parse_combined(self, raw, all_fns, allowed_analysis_types):
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
            analysis_type = self._normalise_combined_analysis_type(
                e.get("analysis_type"), allowed_analysis_types
            )
            if not analysis_type:
                continue

            if analysis_type == "lifecycle":
                source_name = (
                    e.get("free_function")
                    or e.get("teardown_function")
                    or e.get("source_function")
                    or e.get("related_function")
                )
                sink_name = (
                    e.get("use_function")
                    or e.get("sink_function")
                    or e.get("primary_function")
                    or e.get("function_name")
                )
            elif analysis_type == "ownership":
                source_name = (
                    e.get("function_a")
                    or e.get("source_function")
                    or e.get("related_function")
                )
                sink_name = (
                    e.get("function_b")
                    or e.get("sink_function")
                    or e.get("primary_function")
                    or e.get("function_name")
                )
            else:
                source_name = e.get("related_function") or e.get("source_function")
                sink_name = (
                    e.get("function_name")
                    or e.get("sink_function")
                    or e.get("primary_function")
                )

            sink_fn = _lookup_fn(str(sink_name or ""), bn, bu, all_fns)
            source_fn = _lookup_fn(str(source_name or ""), bn, bu, all_fns)
            if not sink_fn:
                continue
            if not source_fn:
                source_fn = sink_fn
            high_risk_cross = analysis_type in {"lifecycle", "ownership"}
            results.append(
                self._finding_from_entry(
                    e,
                    source_fn=source_fn,
                    source_line=source_fn.line_number,
                    sink_fn=sink_fn,
                    sink_line=sink_fn.line_number,
                    path=(
                        [source_fn.unique_name, sink_fn.unique_name]
                        if source_fn.unique_name != sink_fn.unique_name
                        else [sink_fn.unique_name]
                    ),
                    analysis_type=analysis_type,
                    default_vulnerability_type=(
                        "use_after_free" if high_risk_cross else "other"
                    ),
                    default_severity="high" if high_risk_cross else "medium",
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
            results.append(
                self._finding_from_entry(
                    e,
                    source_fn=src_fn,
                    source_line=src_fn.line_number,
                    sink_fn=fn,
                    sink_line=fn.line_number,
                    path=(
                        [src_fn.unique_name, fn.unique_name] if rf else [fn.unique_name]
                    ),
                    analysis_type=analysis_type,
                )
            )
        return results
