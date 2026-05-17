# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Graph-wide supplementary audits for C/C++ reachability review."""

from __future__ import annotations
import logging
import os
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from metis.usage import submit_with_current_context

from .llm_runner import invoke_reachability_prompt
from .domain_hints import format_domain_hints_for_prompt, normalize_domain_hints
from .graph_utils import _chunked
from .supplementary_lenses import (
    _AUTH_KW,
    _COMBINED_GRAPH_LENS_EXAMPLES,
    _COMBINED_GRAPH_LENS_KINDS,
    _COMBINED_GRAPH_LENS_NOTES,
    _FULL_LENS_SPECS,
    _GLOBAL_LIFECYCLE_NAME_RE,
    _HW_STATE_KW,
    _LIFECYCLE_KW,
    _LOCK_EVENT_RE,
    _RELATED_FILE_FUNCTION_KEYWORDS,
    _RESOURCE_KW,
    _REVIEW_LENS_NAMES,
)
from .supplementary_parsing import _parse_combined, _parse_intra, _parse_semantic
from .supplementary_prompts import (
    _COMBINED_GRAPH_SYS,
    _COMBINED_GRAPH_USR,
    _GLOBAL_LIFECYCLE_SYS,
    _INTRA_SYS,
    _INTRA_USR,
    _LOCK_ORDER_SYS,
    _SEM_USR,
)
from .supplementary_selection import (
    _expand_candidates_with_related_file_functions,
    _select_nodes_by_regex,
)
from .source_context import (
    _build_file_grouped_chunks,
    _build_file_grouped_node_chunks,
    _build_globals_code,
    _read_function_body,
)

logger = logging.getLogger("metis")


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
                reasoning_effort=self._reasoning_effort,
            )
            return _parse_combined(raw, fns, frozenset(analysis_types))

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
            reasoning_effort=self._reasoning_effort,
        )
        return _parse_intra(raw, functions)

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
                reasoning_effort=self._reasoning_effort,
            )
            return _parse_intra(raw, chunk_nodes, analysis_type=analysis_type)

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
                reasoning_effort=self._reasoning_effort,
            )
            return _parse_semantic(raw, chunk_nodes, analysis_type=analysis_type)

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
                reasoning_effort=self._reasoning_effort,
            )
            return _parse_semantic(raw, chunk_nodes, analysis_type="global_lifecycle")

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
                reasoning_effort=self._reasoning_effort,
            )
            results.extend(
                _parse_semantic(raw, nodes, analysis_type="lock_order_extraction")
            )
        if cb:
            cb({"event": "lock_order_extraction_done", "findings": len(results)})
        return results
