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
    _COUNTER_SYMMETRY_SYS,
    _ERROR_UNWIND_SYS,
    _GLOBAL_LIFECYCLE_SYS,
    _INTRA_SYS,
    _INTRA_USR,
    _LIFE_SYS,
    _LIFE_USR,
    _LOCK_ORDER_SYS,
    _OWN_SYS,
    _OWN_USR,
    _SEM_SYS,
    _SEM_USR,
    _STATE_SYS,
    _STATE_USR,
    _TARGET_CALLBACK_SYS,
    _TARGET_ORDERING_GAP_SYS,
    _TARGET_PATH_ACCESS_SYS,
    _TARGET_PERMISSION_SYS,
    _TARGET_REFCOUNT_SYS,
    _TARGET_STATE_SYS,
    _TARGET_TOCTOU_SYS,
)
from .finding_normalization import (
    _canonical_fields,
    _lookup_fn,
    _normalise_vuln_type,
)
from .graph_utils import _chunked
from .source_context import (
    _build_file_grouped_chunks,
    _build_file_grouped_node_chunks,
    _build_globals_code,
    _read_function_body,
)

logger = logging.getLogger("metis")


@dataclass(frozen=True)
class _SupplementaryPassSpec:
    name: str
    kind: str
    method_name: str = ""
    sys_prompt: str = ""
    user_prompt: str = _SEM_USR
    user_key: str = "all_functions_code"
    analysis_type: str = ""
    key_a: str = ""
    key_b: str = ""
    pattern: object = None
    include_globals: bool = False
    relation_keywords: object = None
    warning_label: str = ""


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
    r"strlen|strnlen|close)\s*\(",
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

_FULL_PASS_SPECS = (
    _SupplementaryPassSpec("intra_audit", "method", method_name="_pass_intra"),
    _SupplementaryPassSpec(
        "lifecycle_audit",
        "cross",
        sys_prompt=_LIFE_SYS,
        user_prompt=_LIFE_USR,
        analysis_type="lifecycle",
        key_a="free_function",
        key_b="use_function",
    ),
    _SupplementaryPassSpec(
        "ownership_audit",
        "cross",
        sys_prompt=_OWN_SYS,
        user_prompt=_OWN_USR,
        analysis_type="ownership",
        key_a="function_a",
        key_b="function_b",
        include_globals=True,
    ),
    _SupplementaryPassSpec(
        "semantic_audit",
        "semantic",
        sys_prompt=_SEM_SYS,
        include_globals=True,
        warning_label="Semantic",
    ),
    _SupplementaryPassSpec(
        "state_audit",
        "semantic",
        sys_prompt=_STATE_SYS,
        user_prompt=_STATE_USR,
        analysis_type="state_concurrency",
        include_globals=True,
        warning_label="State/concurrency",
    ),
    _SupplementaryPassSpec(
        "targeted_state_order",
        "targeted",
        sys_prompt=_TARGET_STATE_SYS,
        analysis_type="targeted_state_order",
    ),
    _SupplementaryPassSpec(
        "targeted_callback_lifecycle",
        "targeted",
        sys_prompt=_TARGET_CALLBACK_SYS,
        analysis_type="targeted_callback_lifecycle",
        relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS,
    ),
    _SupplementaryPassSpec(
        "targeted_refcount",
        "targeted",
        sys_prompt=_TARGET_REFCOUNT_SYS,
        analysis_type="targeted_refcount",
    ),
    _SupplementaryPassSpec(
        "targeted_permission",
        "targeted",
        sys_prompt=_TARGET_PERMISSION_SYS,
        analysis_type="targeted_permission",
    ),
    _SupplementaryPassSpec(
        "targeted_toctou",
        "targeted",
        sys_prompt=_TARGET_TOCTOU_SYS,
        analysis_type="targeted_toctou",
    ),
    _SupplementaryPassSpec(
        "classic_c_sink",
        "candidate_intra",
        sys_prompt=_CLASSIC_C_SINK_SYS,
        pattern=_CLASSIC_C_SINK_RE,
        analysis_type="classic_c_sink",
    ),
    _SupplementaryPassSpec(
        "error_unwind",
        "candidate_semantic",
        sys_prompt=_ERROR_UNWIND_SYS,
        pattern=_ERROR_UNWIND_RE,
        analysis_type="error_unwind",
        relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS,
    ),
    _SupplementaryPassSpec(
        "counter_symmetry",
        "candidate_semantic",
        sys_prompt=_COUNTER_SYMMETRY_SYS,
        pattern=_COUNTER_RE,
        analysis_type="counter_symmetry",
        relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS,
    ),
    _SupplementaryPassSpec(
        "global_lifecycle", "method", method_name="_pass_global_lifecycle"
    ),
    _SupplementaryPassSpec(
        "lock_order_extraction", "method", method_name="_pass_lock_order"
    ),
    _SupplementaryPassSpec(
        "targeted_ordering_gap",
        "candidate_semantic",
        sys_prompt=_TARGET_ORDERING_GAP_SYS,
        pattern=_ORDERING_GAP_RE,
        analysis_type="targeted_ordering_gap",
        relation_keywords=_RELATED_FILE_FUNCTION_KEYWORDS,
    ),
    _SupplementaryPassSpec(
        "targeted_path_access",
        "candidate_semantic",
        sys_prompt=_TARGET_PATH_ACCESS_SYS,
        pattern=_PATH_ACCESS_RE,
        analysis_type="targeted_path_access",
    ),
)

_REVIEW_PASS_NAMES = {
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
        profile = str(analysis_profile or "full").lower()
        pass_specs = (
            [spec for spec in _FULL_PASS_SPECS if spec.name in _REVIEW_PASS_NAMES]
            if profile == "review"
            else list(_FULL_PASS_SPECS)
        )
        findings = []
        if not pass_specs:
            return findings
        worker_budget = max(1, int(max_workers or 1))
        pass_parallelism = max(1, min(len(pass_specs), worker_budget, 8))
        pass_workers = max(1, worker_budget // pass_parallelism)

        def _run_pass(spec):
            try:
                return self._run_pass_spec(spec, graph, pass_workers, progress_callback)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                logger.warning("%s pass fail: %s", spec.name, exc)
                if progress_callback:
                    progress_callback(
                        {
                            "event": f"{spec.name}_error",
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )
                return []

        if pass_parallelism == 1:
            for spec in pass_specs:
                findings.extend(_run_pass(spec))
        else:
            with ThreadPoolExecutor(max_workers=pass_parallelism) as executor:
                futures = {
                    submit_with_current_context(executor, _run_pass, spec): spec.name
                    for spec in pass_specs
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

    def _run_pass_spec(self, spec, graph, max_workers, cb):
        if spec.kind == "method":
            return getattr(self, spec.method_name)(graph, max_workers, cb)
        if spec.kind == "cross":
            return self._run_chunked_cross_pass(
                graph,
                spec.sys_prompt,
                spec.user_prompt,
                spec.user_key,
                spec.analysis_type,
                spec.key_a,
                spec.key_b,
                self._sm,
                self._st,
                max_workers,
                cb,
                spec.name,
                include_globals=spec.include_globals,
            )
        if spec.kind == "semantic":
            return self._run_chunked_llm_pass(
                graph,
                spec.sys_prompt,
                spec.user_prompt,
                spec.user_key,
                self._sm,
                self._st,
                max_workers,
                cb,
                spec.name,
                lambda raw, fns: self._parse_semantic(
                    raw, fns, analysis_type=spec.analysis_type or "semantic"
                ),
                include_globals=spec.include_globals,
                warning_label=spec.warning_label or None,
            )
        if spec.kind == "targeted":
            return self._run_targeted_pass(
                graph,
                spec.sys_prompt,
                spec.analysis_type,
                max_workers,
                cb,
                spec.name,
                relation_keywords=spec.relation_keywords,
            )
        if spec.kind == "candidate_intra":
            return self._run_candidate_intra_pass(
                graph,
                spec.pattern,
                spec.sys_prompt,
                spec.analysis_type,
                max_workers,
                cb,
                spec.name,
            )
        if spec.kind == "candidate_semantic":
            return self._run_candidate_semantic_pass(
                graph,
                spec.pattern,
                spec.sys_prompt,
                spec.analysis_type,
                max_workers,
                cb,
                spec.name,
                relation_keywords=spec.relation_keywords,
            )
        raise ValueError(f"unknown supplementary pass kind: {spec.kind}")

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
        raw = invoke_reachability_prompt(
            self._p,
            self._u,
            model=self._am,
            max_tokens=self._at,
            system_prompt=_INTRA_SYS,
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
        primary_file, primary_function, primary_line, canonical_key = _canonical_fields(
            entry,
            default_file=sink_fn.file_path,
            default_function=sink_fn.unique_name,
            default_line=sink_line,
        )
        return VulnerabilityFinding(
            id=uuid.uuid4().hex[:16],
            vulnerability_type=_normalise_vuln_type(
                entry.get("vulnerability_type") or default_vulnerability_type
            ),
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

    # All use chunking to avoid blowing context windows.

    def _run_chunked_llm_pass(
        self,
        graph,
        sys_prompt,
        usr_template,
        usr_key,
        model,
        max_tokens,
        max_workers,
        cb,
        event_prefix,
        parse_raw,
        include_globals=False,
        warning_label=None,
        functions=None,
    ):
        fns = list(functions) if functions is not None else list(graph.nodes.values())
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
            raw = invoke_reachability_prompt(
                self._p,
                self._u,
                model=model,
                max_tokens=max_tokens,
                system_prompt=sys_prompt,
                user_prompt=usr_template,
                variables={usr_key: code_chunk},
                reasoning_effort=getattr(self, "_reasoning_effort", None),
            )
            return raw

        if len(chunks) == 1:
            raw = _run_chunk(chunks[0])
            results = parse_raw(raw, fns)
        else:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(chunks))) as ex:
                futs = {
                    submit_with_current_context(ex, _run_chunk, chunk): i
                    for i, chunk in enumerate(chunks)
                }
                for fut in as_completed(futs):
                    try:
                        raw = fut.result()
                        results.extend(parse_raw(raw, fns))
                    except Exception as e:
                        logger.warning(
                            "%s chunk fail: %s", warning_label or event_prefix, e
                        )

        if cb:
            cb({"event": f"{event_prefix}_done", "findings": len(results)})
        return results

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
        return self._run_chunked_llm_pass(
            graph,
            sys_prompt,
            usr_template,
            usr_key,
            model,
            max_tokens,
            max_workers,
            cb,
            event_prefix,
            lambda raw, fns: self._parse_cross(raw, fns, analysis_type, key_a, key_b),
            include_globals=include_globals,
        )

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
        return self._run_chunked_llm_pass(
            graph,
            sys_prompt,
            _SEM_USR,
            "all_functions_code",
            self._sm,
            self._st,
            max_workers,
            cb,
            event_prefix,
            lambda raw, fns: self._parse_semantic(
                raw, fns, analysis_type=analysis_type
            ),
            include_globals=True,
            functions=fns,
        )

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
            raw = invoke_reachability_prompt(
                self._p,
                self._u,
                model=self._sm,
                max_tokens=self._st,
                system_prompt=sys_prompt,
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
            raw = invoke_reachability_prompt(
                self._p,
                self._u,
                model=self._sm,
                max_tokens=self._st,
                system_prompt=sys_prompt,
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
            raw = invoke_reachability_prompt(
                self._p,
                self._u,
                model=self._sm,
                max_tokens=self._st,
                system_prompt=_GLOBAL_LIFECYCLE_SYS,
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
            raw = invoke_reachability_prompt(
                self._p,
                self._u,
                model=self._sm,
                max_tokens=self._st,
                system_prompt=_LOCK_ORDER_SYS,
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
            results.append(
                self._finding_from_entry(
                    e,
                    source_fn=fa,
                    source_line=fa.line_number,
                    sink_fn=fb,
                    sink_line=fb.line_number,
                    path=[fa.unique_name, fb.unique_name],
                    analysis_type=analysis_type,
                    default_vulnerability_type="use_after_free",
                    default_severity="high",
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
