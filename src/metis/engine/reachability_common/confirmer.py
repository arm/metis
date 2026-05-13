# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""LLM confirmation for deterministic reachability paths."""

from __future__ import annotations
import logging
import os
import threading
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.usage import submit_with_current_context
from metis.utils import parse_json_output

from .models import VulnerabilityFinding
from .utils import (
    _canonical_fields,
    _chat_model_kwargs,
    _chunked,
    _dedupe_paths,
    _normalise_vuln_type,
    _read_function_body,
    _safe_int,
    _same_file_ref,
)

logger = logging.getLogger("metis")
_CANONICAL_FINDING_INSTRUCTIONS = """\

For every finding include canonical ownership fields:
{{"primary_file": "src/example.c", "primary_function": "example_function",
"primary_line": 123,
"canonical_key": "src/example.c:example_function:vulnerability_family:root_cause_token"}}
Choose primary_file/primary_function/primary_line as the location of the actual defective code,
not merely the source, caller, helper, or path endpoint.
If the same root cause appears through multiple paths, use the same canonical_key.
canonical_key should be stable and concise: file:function:vulnerability_family:root_cause_token.
Be conservative. Report each distinct root cause once.
Do not report a caller/path duplicate if the same primary defect is already represented.
Do not assign a bug to a helper/header unless the actual defective code is in that helper/header."""

_CONFIRM_SYS = (
    """\
You are a security researcher specializing in C and C++ code analysis.
You are given reachable call paths from attacker input sources to reachable endpoints, with relevant source code.
Endpoints are not necessarily security sinks. Inspect every function on the path and report the actual vulnerable
operation wherever it appears on that path.
For EACH path determine if it contains a real exploitable vulnerability:
1. Does attacker-controlled execution, input, state, or object lifetime reach the vulnerable operation through the path?
2. Are there sanitization, bounds, permission, or lifecycle checks that prevent exploitation?
3. Is the dangerous operation or missing check truly reachable as called?
Return ONLY valid JSON:
{{"findings": [{{"path_index": 0, "is_vulnerable": true, "vulnerability_type": "buffer_overflow",
"severity": "high", "confidence": "high", "description": "...", "root_cause": "...", "evidence": "..."}}]}}
vulnerability_type: buffer_overflow, use_after_free, double_free, double_close, null_deref, command_injection, \
format_string, integer_overflow, path_traversal, race_condition, uninitialized_memory, type_confusion, \
out_of_bounds, refcount_imbalance, state_order, lock_order, stale_after_unlock, accounting_drift, \
missing_auth, permission_mismatch, info_leak, teardown_race, partial_cleanup, deferred_uaf, stale_state, \
toctou, other.
severity: critical, high, medium, low. confidence: high, medium, low. Be conservative."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_CONFIRM_USR = "{paths_section}\n\n{code_section}"

# --- Inbound: bugs rooted IN the target file ---

_FILE_CONFIRM_SYS = (
    """\
You are a security researcher specializing in C and C++ code analysis.
You are reviewing ONE target file from a larger codebase.
You are given:
- reachable call paths from external or attacker-controlled sources
- the relevant code from the target file
- supporting code for upstream/downstream functions on the path
Only report a vulnerability when the primary bug mechanism is actually present in the TARGET FILE code shown.
If the real root cause is not in the target file, do not report it for this target file.
For EACH path determine if it is a real exploitable vulnerability in the target file:
1. Does attacker input actually propagate through the path into the target file logic?
2. Does the target file contain the missing validation, unsafe state transition, or dangerous sink usage?
3. Are there checks or lifecycle constraints that make the path non-exploitable?
4. Is the root cause in the target file rather than merely elsewhere on the path?
Return ONLY valid JSON:
{{"findings": [{{"path_index": 0, "is_vulnerable": true, "vulnerability_type": "buffer_overflow",
"severity": "high", "confidence": "high", "description": "...", "root_cause": "...", "evidence": "..."}}]}}
vulnerability_type: buffer_overflow, use_after_free, double_free, null_deref, command_injection, format_string, \
integer_overflow, path_traversal, race_condition, uninitialized_memory, type_confusion, out_of_bounds, \
state_order, lock_order, stale_after_unlock, accounting_drift, missing_auth, permission_mismatch, \
info_leak, teardown_race, partial_cleanup, deferred_uaf, stale_state, toctou, other.
severity: critical, high, medium, low. confidence: high, medium, low. Be conservative."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_FILE_CONFIRM_USR = """Target file: {target_file}
{paths_section}
== TARGET FILE CODE ==
{target_file_code}
== RELATED PATH CODE ==
{related_code_section}
"""

# --- Cross-file: bugs involving the target file's functions used by OTHER files ---

_CROSS_FILE_SYS = (
    """\
You are a security researcher specializing in C and C++ code analysis.

You are reviewing how functions defined in the FOCUS FILE are used by OTHER files \
in the codebase. The goal is to find vulnerabilities that appear during \
cross-file interactions, for example when the focus file's functions are called, \
consumed, or depended upon by code in other files.

Report a vulnerability when:
- A function defined in the FOCUS FILE returns a value that callers in OTHER files \
  misinterpret (e.g. treating a permission level as boolean, ignoring error codes)
- A function in the FOCUS FILE produces output (string, buffer, pointer) that callers \
  in other files consume unsafely (e.g. copying into a smaller buffer without checking)
- A function in the FOCUS FILE frees/releases a resource, and callers in other files \
  also free/release the same resource, creating a double-free or double-close
- A function in the FOCUS FILE creates ambiguous ownership semantics that cause callers \
  to mismanage resources (e.g. parse function frees on some error paths but not others, \
  caller always frees)
- A function in the FOCUS FILE sanitizes or transforms data but leaves a \
  length/size field stale, causing callers to use stale metadata
- A function in the FOCUS FILE assigns a state flag or readiness indicator that callers \
  depend on, but the flag is set before prerequisite operations complete

For each finding, identify both the focus-file function involved AND the caller \
function in the other file where the misuse occurs.

Return ONLY valid JSON:
{{"findings": [{{"path_index": 0, "is_vulnerable": true, "vulnerability_type": "boolean_coercion",
"severity": "high", "confidence": "high",
"description": "...", "root_cause": "...", "evidence": "..."}}]}}

vulnerability_type: boolean_coercion, double_free, double_close, buffer_overflow, \
use_after_free, wrong_constant, stale_length, type_confusion, state_order, \
refcount_imbalance, deferred_uaf, stale_state, partial_cleanup, other.
severity: critical, high, medium, low. confidence: high, medium, low."""
    + _CANONICAL_FINDING_INSTRUCTIONS
)

_CROSS_FILE_USR = """Focus file: {target_file}

{paths_section}

== FOCUS FILE CODE (functions defined here) ==
{target_file_code}

== CALLER CODE (other files that use the focus file's functions) ==
{related_code_section}
"""


class VulnerabilityConfirmer:
    """Confirm whether selected source-rooted paths contain real C/C++ defects."""

    def __init__(
        self,
        llm_provider,
        model,
        usage_runtime,
        codebase_path,
        max_tokens=4096,
        reasoning_effort=None,
    ):
        self._p = llm_provider
        self._m = model
        self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path)
        self._t = max_tokens
        self._reasoning_effort = reasoning_effort

    # --- Bulk confirmation for full-codebase reachability review ---

    def confirm_parallel(self, paths, graph, *, max_workers=8, progress_callback=None):
        if not paths:
            return []
        groups = defaultdict(list)
        for p in paths:
            groups[p.sink].append(p)
        total = len(groups)
        all_f = []
        lock = threading.Lock()
        done = [0]
        if progress_callback:
            progress_callback({"event": "confirmation_start", "total": total})
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {
                submit_with_current_context(ex, self._group, sn, gp, graph): sn
                for sn, gp in groups.items()
            }
            for fut in as_completed(futs):
                sn = futs[fut]
                try:
                    findings = fut.result()
                    with lock:
                        all_f.extend(findings)
                except Exception as e:
                    logger.warning("Confirm fail %s: %s", sn, e)
                    if progress_callback:
                        progress_callback(
                            {
                                "event": "confirmation_error",
                                "sink": sn,
                                "endpoint": sn,
                                "error": f"{type(e).__name__}: {e}",
                            }
                        )
                with lock:
                    done[0] += 1
                if progress_callback:
                    progress_callback(
                        {
                            "event": "confirmation_progress",
                            "completed": done[0],
                            "total": total,
                            "sink": sn,
                            "endpoint": sn,
                        }
                    )
        if progress_callback:
            progress_callback({"event": "confirmation_done", "confirmed": len(all_f)})
        return all_f

    def _group(self, sink_name, paths, graph):
        batch = paths[:8]
        needed = {}
        for p in batch:
            for u in p.path:
                n = graph.get_node(u)
                if n:
                    needed[u] = n
        ps = ["== CANDIDATE PATHS =="]
        for i, p in enumerate(batch):
            sn, sk = graph.get_node(p.source), graph.get_node(p.sink)
            ps.append(f"\nPath {i}:\n Chain: {' -> '.join(p.path)}")
            if sn:
                ps.append(
                    f" Source: {sn.unique_name} (line {sn.line_number}) - {sn.source_reason}"
                )
            if sk:
                endpoint_note = (
                    f"[{sk.sink_type}] - {sk.sink_reason}"
                    if sk.is_sink
                    else "[reachable endpoint; inspect the whole path]"
                )
                ps.append(
                    f" Endpoint: {sk.unique_name} (line {sk.line_number}) {endpoint_note}"
                )
        cs = ["== SOURCE CODE =="]
        for u, n in needed.items():
            b = _read_function_body(self._cb, n)
            if b:
                cs.append(f"\n--- {u} (line {n.line_number}) ---\n{b}")
        kw = _chat_model_kwargs(
            self._u, reasoning_effort=getattr(self, "_reasoning_effort", None)
        )
        chat = self._p.get_chat_model(
            model=self._m, max_tokens=self._t, temperature=0.1, **kw
        )
        prompt = ChatPromptTemplate.from_messages(
            [("system", _CONFIRM_SYS), ("user", _CONFIRM_USR)]
        )
        raw = (
            (prompt | chat | StrOutputParser())
            .invoke({"paths_section": "\n".join(ps), "code_section": "\n".join(cs)})
            .strip()
        )
        return self._parse_confirm(raw, batch, graph)

    def _parse_confirm(self, raw, batch, graph, *, target_file=None):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return []
        fl = parsed.get("findings")
        if not isinstance(fl, list):
            return []
        results = []
        for e in fl:
            if not isinstance(e, dict) or not e.get("is_vulnerable"):
                continue
            idx = _safe_int(e.get("path_index"), -1)
            if idx < 0 or idx >= len(batch):
                continue
            rp = batch[idx]
            sn = graph.get_node(rp.source)
            sk = graph.get_node(rp.sink)
            source_file = sn.file_path if sn else ""
            source_line = sn.line_number if sn else 0
            sink_file = sk.file_path if sk else ""
            sink_line = sk.line_number if sk else 0
            explicit_primary_file = str(e.get("primary_file") or "").strip()
            if (
                target_file
                and explicit_primary_file
                and not _same_file_ref(explicit_primary_file, target_file, self._cb)
            ):
                continue
            primary_file, primary_function, primary_line, canonical_key = (
                _canonical_fields(
                    e,
                    default_file=sink_file or source_file,
                    default_function=rp.sink or rp.source,
                    default_line=sink_line or source_line,
                )
            )
            results.append(
                VulnerabilityFinding(
                    id=uuid.uuid4().hex[:16],
                    vulnerability_type=_normalise_vuln_type(
                        e.get("vulnerability_type") or rp.sink_type or "other"
                    ),
                    severity=str(e.get("severity") or "medium"),
                    confidence=str(e.get("confidence") or "medium"),
                    source_function=rp.source,
                    source_file=source_file,
                    source_line=source_line,
                    sink_function=rp.sink,
                    sink_file=sink_file,
                    sink_line=sink_line,
                    path=list(rp.path),
                    description=str(e.get("description") or ""),
                    root_cause=str(e.get("root_cause") or ""),
                    evidence=str(e.get("evidence") or ""),
                    analysis_type="reachability",
                    primary_file=primary_file,
                    primary_function=primary_function,
                    primary_line=primary_line,
                    canonical_key=canonical_key,
                )
            )
        return results

    def confirm_for_file(
        self, target_file, paths, graph, *, max_workers=4, progress_callback=None
    ):
        paths = _dedupe_paths(paths)
        if not paths:
            return []
        batches = list(_chunked(paths, 8))
        all_findings = []
        with ThreadPoolExecutor(
            max_workers=max(1, min(max_workers, len(batches)))
        ) as ex:
            futs = {
                submit_with_current_context(
                    ex, self._confirm_file_batch, target_file, batch, graph
                ): idx
                for idx, batch in enumerate(batches)
            }
            for fut in as_completed(futs):
                try:
                    all_findings.extend(fut.result())
                except Exception as e:
                    logger.warning(
                        "Error confirming inbound paths for %s: %s", target_file, e
                    )
        return all_findings

    def _confirm_file_batch(self, target_file, batch, graph):
        target_nodes, related_nodes = {}, {}
        for p in batch:
            for u in p.path:
                n = graph.get_node(u)
                if not n:
                    continue
                if n.file_path == target_file:
                    target_nodes[u] = n
                else:
                    related_nodes[u] = n
        ps = ["== CANDIDATE PATHS =="]
        for i, p in enumerate(batch):
            sn, sk = graph.get_node(p.source), graph.get_node(p.sink)
            ps.append(f"\nPath {i}:\n Chain: {' -> '.join(p.path)}")
            if sn:
                ps.append(
                    f" Source: {sn.unique_name} (line {sn.line_number}) - {sn.source_reason}"
                )
            if sk:
                ps.append(
                    f" Sink: {sk.unique_name} (line {sk.line_number}) [{sk.sink_type}] - {sk.sink_reason}"
                )
        tc = ["-- Functions from target file --"]
        for u, n in target_nodes.items():
            body = _read_function_body(self._cb, n, 5000)
            if body:
                tc.append(f"\n--- {u} (line {n.line_number}) ---\n{body}")
        rc = ["-- Supporting code from other files --"]
        for u, n in related_nodes.items():
            body = _read_function_body(self._cb, n, 2500)
            if body:
                rc.append(f"\n--- {u} (line {n.line_number}) ---\n{body}")
        kw = _chat_model_kwargs(
            self._u, reasoning_effort=getattr(self, "_reasoning_effort", None)
        )
        chat = self._p.get_chat_model(
            model=self._m, max_tokens=self._t, temperature=0.1, **kw
        )
        prompt = ChatPromptTemplate.from_messages(
            [("system", _FILE_CONFIRM_SYS), ("user", _FILE_CONFIRM_USR)]
        )
        raw = (
            (prompt | chat | StrOutputParser())
            .invoke(
                {
                    "target_file": target_file,
                    "paths_section": "\n".join(ps),
                    "target_file_code": "\n".join(tc),
                    "related_code_section": "\n".join(rc),
                }
            )
            .strip()
        )
        return self._parse_confirm(raw, batch, graph, target_file=target_file)

    def confirm_cross_file(
        self, target_file, paths, graph, *, max_workers=4, progress_callback=None
    ):
        """Find bugs where OTHER files misuse functions defined in target_file."""
        paths = _dedupe_paths(paths)
        if not paths:
            return []
        batches = list(_chunked(paths, 8))
        all_findings = []
        with ThreadPoolExecutor(
            max_workers=max(1, min(max_workers, len(batches)))
        ) as ex:
            futs = {
                submit_with_current_context(
                    ex, self._confirm_cross_file_batch, target_file, batch, graph
                ): idx
                for idx, batch in enumerate(batches)
            }
            for fut in as_completed(futs):
                try:
                    all_findings.extend(fut.result())
                except Exception as e:
                    logger.warning(
                        "Error confirming cross-file paths for %s: %s", target_file, e
                    )
        return all_findings

    def _confirm_cross_file_batch(self, target_file, batch, graph):
        target_nodes, caller_nodes = {}, {}
        for p in batch:
            for u in p.path:
                n = graph.get_node(u)
                if not n:
                    continue
                if n.file_path == target_file:
                    target_nodes[u] = n
                else:
                    caller_nodes[u] = n

        if not target_nodes or not caller_nodes:
            return []

        ps = ["== PATHS INVOLVING FOCUS FILE FUNCTIONS =="]
        for i, p in enumerate(batch):
            sn, sk = graph.get_node(p.source), graph.get_node(p.sink)
            ps.append(f"\nPath {i}:\n Chain: {' -> '.join(p.path)}")
            if sn:
                ps.append(
                    f" Source: {sn.unique_name} (line {sn.line_number}) - {sn.source_reason}"
                )
            if sk:
                ps.append(
                    f" Sink: {sk.unique_name} (line {sk.line_number}) [{sk.sink_type}] - {sk.sink_reason}"
                )
            focus_fns = [
                u
                for u in p.path
                if graph.get_node(u) and graph.get_node(u).file_path == target_file
            ]
            if focus_fns:
                ps.append(f" Focus-file functions on this path: {', '.join(focus_fns)}")

        tc = ["-- FOCUS FILE: functions defined here --"]
        for u, n in target_nodes.items():
            body = _read_function_body(self._cb, n, 5000)
            if body:
                tc.append(f"\n--- {u} (line {n.line_number}) ---\n{body}")

        rc = ["-- CALLERS: code in other files that uses focus-file functions --"]
        for u, n in caller_nodes.items():
            body = _read_function_body(self._cb, n, 3000)
            if body:
                rc.append(
                    f"\n--- {u} (line {n.line_number} in {n.file_path}) ---\n{body}"
                )

        kw = _chat_model_kwargs(
            self._u, reasoning_effort=getattr(self, "_reasoning_effort", None)
        )
        chat = self._p.get_chat_model(
            model=self._m, max_tokens=self._t, temperature=0.1, **kw
        )
        prompt = ChatPromptTemplate.from_messages(
            [("system", _CROSS_FILE_SYS), ("user", _CROSS_FILE_USR)]
        )
        raw = (
            (prompt | chat | StrOutputParser())
            .invoke(
                {
                    "target_file": target_file,
                    "paths_section": "\n".join(ps),
                    "target_file_code": "\n".join(tc),
                    "related_code_section": "\n".join(rc),
                }
            )
            .strip()
        )

        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return []
        fl = parsed.get("findings")
        if not isinstance(fl, list):
            return []
        results = []
        for e in fl:
            if not isinstance(e, dict) or not e.get("is_vulnerable"):
                continue
            idx = _safe_int(e.get("path_index"), -1)
            if idx < 0 or idx >= len(batch):
                continue
            rp = batch[idx]
            sn = graph.get_node(rp.source)
            sk = graph.get_node(rp.sink)
            focus_fn = None
            for u in rp.path:
                n = graph.get_node(u)
                if n and n.file_path == target_file:
                    focus_fn = n
                    break
            sink_file = target_file
            sink_fn = focus_fn.unique_name if focus_fn else rp.sink
            sink_line = (
                focus_fn.line_number if focus_fn else (sk.line_number if sk else 0)
            )
            source_file = sn.file_path if sn else ""
            source_line = sn.line_number if sn else 0
            primary_file, primary_function, primary_line, canonical_key = (
                _canonical_fields(
                    e,
                    default_file=sink_file or source_file,
                    default_function=sink_fn or rp.source,
                    default_line=sink_line or source_line,
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
                    source_function=rp.source,
                    source_file=source_file,
                    source_line=source_line,
                    sink_function=sink_fn,
                    sink_file=sink_file,
                    sink_line=sink_line,
                    path=list(rp.path),
                    description=str(e.get("description") or ""),
                    root_cause=str(e.get("root_cause") or ""),
                    evidence=str(e.get("evidence") or ""),
                    analysis_type="cross_file",
                    primary_file=primary_file,
                    primary_function=primary_function,
                    primary_line=primary_line,
                    canonical_key=canonical_key,
                )
            )
        return results
