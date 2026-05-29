# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""LLM confirmation for deterministic reachability paths."""

from __future__ import annotations
import logging
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from metis.reachability_settings import DEFAULT_REACHABILITY_WORKERS
from metis.usage import submit_with_current_context

from .finding_normalization import (
    _finding_from_llm_entry,
    _safe_int,
    _same_file_ref,
)
from .graph_utils import _chunked, _dedupe_paths
from .llm_runner import invoke_reachability_prompt, reachability_response_payload
from .models import (
    ALLOWED_VULNERABILITY_TYPES,
    ReachabilityConfirmationResponseModel,
)
from .prompt_guidance import TRIAGE_NOISE_FILTER_GUIDANCE
from .source_context import _read_function_body

logger = logging.getLogger("metis")


def _emit_progress(callback, event, **payload):
    if callback:
        callback({"event": event, **payload})


def _output_constraints(no_finding_guidance):
    allowed_vulnerability_types = ", ".join(ALLOWED_VULNERABILITY_TYPES)
    return f"""\
Use the structured findings schema supplied by the caller.
For path confirmation, each finding must include path_index and is_vulnerable.
vulnerability_type must exactly be one of: {allowed_vulnerability_types}.
Use out_of_bounds for all OOB read/write/index variants, partial_cleanup for
error-unwind/rollback/resource-leak variants, and use_after_free for dangling
use-after-release lifetime variants unless a narrower allowed type fits better.
cwe must be the best matching CWE ID such as CWE-120 when known, otherwise an empty string.
severity must be exactly one of: critical, high, medium, low.
confidence must be exactly one of: high, medium, low.
{TRIAGE_NOISE_FILTER_GUIDANCE}
Be conservative. {no_finding_guidance}"""


_CANONICAL_FINDING_INSTRUCTIONS = """\

For every finding include canonical ownership fields: primary_file, primary_function,
primary_line, root_cause_id, and canonical_key.
Choose primary_file/primary_function/primary_line as the location of the actual defective code,
not merely the source, caller, helper, or path endpoint.
Use the exact shown function identifier for primary_function when available.
Primary location rules:
- Memory, path, format-string, and command bugs: primary_line is the unsafe call,
  size calculation, open/check pair, or unchecked data use.
- Missing auth/permission bugs: primary_line is the privileged operation or dispatch
  that lacks the correct check, not the permission helper.
- State/order bugs: primary_line is the premature state publication, such as the
  ready/enabled/powered assignment, not a later consumer.
- Cleanup/rollback bugs: primary_line is the failure branch, return, goto, publish,
  or cleanup point where the required rollback/release is missing.
- Lifecycle/use-after-free bugs: primary_line is the use/deref/callback that can
  observe ended lifetime; put the lifetime-ending function in related_function.
- Refcount/accounting bugs: primary_line is the get/put/ref/unref/count update, or
  the paired create/destroy/map/unmap path where the update is missing.
root_cause_id must be a stable short snake_case token for the specific root cause.
Use the same root_cause_id and canonical_key for the same root cause across different
paths, chunks, or lenses.
Do not include caller/path/source names in root_cause_id or canonical_key unless the
caller itself contains the defect.
Include a concise mitigation field that recommends a fix, not a restatement of root_cause or evidence.
Be conservative. Report each distinct root cause once.
Do not report a caller/path duplicate if the same primary defect is already represented.
Do not assign a bug to a helper/header unless the actual defective code is in that helper/header."""


def _confirm_system_prompt(body, no_finding_guidance):
    return (
        body
        + _output_constraints(no_finding_guidance)
        + _CANONICAL_FINDING_INSTRUCTIONS
    )


_CONFIRM_SYS = _confirm_system_prompt(
    """\
You are a security researcher specializing in C and C++ code analysis.
You are given reachable call paths from tree-sitter graph sources to reachable endpoints, with relevant source code.
Endpoints are not necessarily security sinks. Inspect every function on the path and report the actual vulnerable
operation wherever it appears on that path.
For EACH path determine if it contains a real exploitable vulnerability:
1. Does attacker-controlled execution, input, state, or object lifetime reach the vulnerable operation through the path?
2. Are there sanitization, bounds, permission, or lifecycle checks that prevent exploitation?
3. Is the dangerous operation or missing check truly reachable as called?
""",
    "If the path does not prove a vulnerability, return no findings.",
)

_CONFIRM_USR = "{paths_section}\n\n{code_section}"

# --- Inbound: bugs rooted IN the target file ---

_FILE_CONFIRM_SYS = _confirm_system_prompt(
    """\
You are a security researcher specializing in C and C++ code analysis.
You are reviewing ONE target file from a larger codebase.
You are given:
- reachable call paths from tree-sitter graph sources
- the relevant code from the target file
- supporting code for upstream/downstream functions on the path
Only report a vulnerability when the primary bug mechanism is actually present in the TARGET FILE code shown.
If the real root cause is not in the target file, do not report it for this target file.
For EACH path determine if it is a real exploitable vulnerability in the target file:
1. Does attacker input actually propagate through the path into the target file logic?
2. Does the target file contain the missing validation, unsafe state transition, or dangerous sink usage?
3. Are there checks or lifecycle constraints that make the path non-exploitable?
4. Is the root cause in the target file rather than merely elsewhere on the path?
""",
    "If the target file does not contain the primary bug, return no findings.",
)

_FILE_CONFIRM_USR = """Target file: {target_file}
{paths_section}
== TARGET FILE CODE ==
{target_file_code}
== RELATED PATH CODE ==
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

    def _path_nodes(self, batch, graph):
        nodes = {}
        for p in batch:
            for u in p.path:
                n = graph.get_node(u)
                if n:
                    nodes[u] = n
        return nodes

    def _paths_section(self, batch, graph, endpoint_fallback):
        section = ["== CANDIDATE PATHS =="]
        for i, p in enumerate(batch):
            sn, sk = graph.get_node(p.source), graph.get_node(p.sink)
            section.append(f"\nPath {i}:\n Chain: {' -> '.join(p.path)}")
            if sn:
                section.append(
                    f" Source: {sn.unique_name} (line {sn.line_number}) - {sn.source_reason}"
                )
            if sk:
                endpoint_note = (
                    f"[{sk.sink_type}] - {sk.sink_reason}"
                    if sk.is_sink
                    else endpoint_fallback
                )
                section.append(
                    f" Endpoint: {sk.unique_name} (line {sk.line_number}) {endpoint_note}"
                )
        return "\n".join(section)

    def _code_section(self, title, nodes, *, max_chars=None):
        section = [title]
        for u, n in nodes.items():
            body = (
                _read_function_body(self._cb, n)
                if max_chars is None
                else _read_function_body(self._cb, n, max_chars)
            )
            if body:
                section.append(f"\n--- {u} (line {n.line_number}) ---\n{body}")
        return "\n".join(section)

    def _run_batches(
        self,
        batches,
        worker,
        *,
        max_workers,
        progress_callback=None,
    ):
        results = []
        total = len(batches)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                submit_with_current_context(executor, worker, batch): key
                for key, batch in batches
            }
            for completed, future in enumerate(as_completed(futures), start=1):
                key = futures[future]
                try:
                    results.extend(future.result())
                except Exception as exc:
                    logger.warning(
                        "Reachability confirmation failed for %s: %s", key, exc
                    )
                _emit_progress(
                    progress_callback,
                    "confirmation_progress",
                    completed=completed,
                    total=total,
                    sink=key,
                    endpoint=key,
                )
        return results

    # --- Bulk confirmation for full-codebase reachability review ---

    def confirm_paths(
        self,
        paths,
        graph,
        *,
        max_workers=DEFAULT_REACHABILITY_WORKERS,
        progress_callback=None,
    ):
        if not paths:
            return []
        groups = defaultdict(list)
        for p in paths:
            groups[p.sink].append(p)
        batches = [
            (sink_name, batch)
            for sink_name, group_paths in groups.items()
            for batch in _chunked(group_paths, 8)
        ]
        total = len(batches)
        _emit_progress(progress_callback, "confirmation_start", total=total)
        findings = self._run_batches(
            batches,
            lambda batch: self._confirm_batch(batch, graph),
            max_workers=max_workers,
            progress_callback=progress_callback,
        )
        _emit_progress(progress_callback, "confirmation_done", confirmed=len(findings))
        return findings

    def _confirm_batch(self, paths, graph):
        batch = list(paths)
        raw = invoke_reachability_prompt(
            self._p,
            self._u,
            model=self._m,
            max_tokens=self._t,
            system_prompt=_CONFIRM_SYS,
            user_prompt=_CONFIRM_USR,
            variables={
                "paths_section": self._paths_section(
                    batch, graph, "[reachable endpoint; inspect the whole path]"
                ),
                "code_section": self._code_section(
                    "== SOURCE CODE ==", self._path_nodes(batch, graph)
                ),
            },
            response_model=ReachabilityConfirmationResponseModel,
            reasoning_effort=self._reasoning_effort,
        )
        return self._parse_confirm(raw, batch, graph)

    def _parse_confirm(self, raw, batch, graph, *, target_file=None):
        parsed = reachability_response_payload(raw)
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
            results.append(
                _finding_from_llm_entry(
                    e,
                    source_function=rp.source,
                    source_file=source_file,
                    source_line=source_line,
                    sink_function=rp.sink,
                    sink_file=sink_file,
                    sink_line=sink_line,
                    path=rp.path,
                    analysis_type="reachability",
                    default_file=sink_file or source_file,
                    default_function=rp.sink or rp.source,
                    default_line=sink_line or source_line,
                    default_vulnerability_type=rp.sink_type or "other",
                )
            )
        return results

    def confirm_paths_for_file(self, target_file, paths, graph, *, max_workers=4):
        paths = _dedupe_paths(paths)
        if not paths:
            return []
        batches = [(target_file, batch) for batch in _chunked(paths, 8)]

        return self._run_batches(
            batches,
            lambda batch: self._confirm_file_batch(target_file, batch, graph),
            max_workers=max(1, min(max_workers, len(batches))),
        )

    def _confirm_file_batch(self, target_file, batch, graph):
        target_nodes, related_nodes = {}, {}
        for u, n in self._path_nodes(batch, graph).items():
            if n.file_path == target_file:
                target_nodes[u] = n
            else:
                related_nodes[u] = n
        raw = invoke_reachability_prompt(
            self._p,
            self._u,
            model=self._m,
            max_tokens=self._t,
            system_prompt=_FILE_CONFIRM_SYS,
            user_prompt=_FILE_CONFIRM_USR,
            variables={
                "target_file": target_file,
                "paths_section": self._paths_section(
                    batch,
                    graph,
                    "[reachable endpoint; inspect the target-file path]",
                ),
                "target_file_code": self._code_section(
                    "-- Functions from target file --", target_nodes, max_chars=5000
                ),
                "related_code_section": self._code_section(
                    "-- Supporting code from other files --",
                    related_nodes,
                    max_chars=2500,
                ),
            },
            response_model=ReachabilityConfirmationResponseModel,
            reasoning_effort=self._reasoning_effort,
        )
        return self._parse_confirm(raw, batch, graph, target_file=target_file)
