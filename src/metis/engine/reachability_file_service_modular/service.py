# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Partial reachability service used by ``review_file --mode partial``."""

from __future__ import annotations

from .common import *

from .context import *
from .graph import *
from .detectors import *
from .reviewer import *
from .filters import *

class PartialReachabilityFileService:
    """Coordinate indexing, context selection, detectors, LLM review, and output."""

    def __init__(self, config: EngineConfig, repository: EngineRepository, llm_provider, usage_runtime):
        self._config = config
        self._repository = repository
        self._llm_provider = llm_provider
        self._usage_runtime = usage_runtime
        self._symbol_index: SymbolIndex | None = None
        self._index_lock = threading.Lock()

    def review_file(
        self,
        file_path,
        *,
        extraction_model="gpt-4.1-mini",
        review_model=None,
        max_workers=8,
        context_budget=250,
        max_paths_per_sink=3,
        reasoning_effort=None,
        progress_callback=None,
    ):
        abs_target, rel_target = self._normalize_target_file(file_path)
        if os.path.splitext(rel_target)[1].lower() not in _C_CPP_EXTS:
            return None

        index = self._ensure_symbol_index(progress_callback=progress_callback)
        cache = PartialAnalysisCache(self._config.codebase_path, index)
        target_nodes, target_globals = self._extract_target(
            abs_target, rel_target, extraction_model, max_workers, progress_callback, cache)

        caps = PartialContextCaps(max_total_context_functions=max(25, int(context_budget or 250)))
        if progress_callback:
            progress_callback({"event": "partial_context_start", "file": rel_target})
        context_builder = PartialContextBuilder(self._config.codebase_path, caps, cache)
        context = context_builder.build_for_file(rel_target, target_nodes, index)
        if target_globals:
            context.globals = self._merge_globals(context.globals, target_globals)
        context_builder.expand_companions(context, index, progress_callback=progress_callback)

        # Detector notes do not become findings directly; they choose focused
        # prompts and add concrete evidence to the partial review context.
        detector_result = PartialCandidateDetector(self._config.codebase_path, cache).detect(
            index, rel_target, context.target_nodes, context)
        self._merge_detector_context(context, detector_result)
        if progress_callback:
            progress_callback({
                "event": "partial_detectors_done",
                "state_publication": len(detector_result.state_publication_notes),
                "publish_rollback": len(detector_result.publish_rollback_notes),
                "allocation_arithmetic": len(detector_result.allocation_arithmetic_notes),
                "copy_contracts": len(detector_result.copy_contract_notes),
                "cleanup_symmetry": len(detector_result.cleanup_symmetry_notes),
                "cleanup_ledger": len(detector_result.cleanup_ledger_notes),
                "suspend_cleanup_ledger": len(detector_result.suspend_cleanup_ledger_notes),
                "accounting_drift": len(detector_result.accounting_drift_notes),
                "arithmetic_chain": len(detector_result.arithmetic_chain_notes),
                "alias_extent_mismatch": len(detector_result.alias_extent_mismatch_notes),
                "size_propagation": len(detector_result.size_propagation_notes),
                "suspend_size_sink": len(detector_result.suspend_size_sink_notes),
                "resource_binding": len(detector_result.resource_binding_notes),
                "resource_validation": len(detector_result.resource_validation_notes),
                "async_order": len(detector_result.async_order_notes),
                "fault_clear_order": len(detector_result.fault_clear_order_notes),
                "stale_tracker": len(detector_result.stale_tracker_notes),
                "region_replace_erase": len(detector_result.region_replace_erase_notes),
                "metadata_type_confusion": len(detector_result.metadata_type_confusion_notes),
                "pm_sequence": len(detector_result.pm_sequence_notes),
                "pm_callback_order": len(detector_result.pm_callback_order_notes),
                "secondary_omission": len(detector_result.secondary_omission_notes),
                "zero_count_underflow": len(detector_result.zero_count_underflow_notes),
                "owner_liveness_allocation": len(detector_result.owner_liveness_notes),
                "user_buffer_permission": len(detector_result.user_buffer_permission_notes),
                "zone_shrink_validation": len(detector_result.zone_shrink_notes),
                "success_path_cleanup": len(detector_result.success_path_cleanup_notes),
                "jit_lock_protocol": len(detector_result.jit_lock_protocol_notes),
                "teardown_order": len(detector_result.teardown_order_notes),
                "queue_publish_init": len(detector_result.queue_publish_init_notes),
                "fd_reuse_race": len(detector_result.fd_reuse_notes),
                "debugfs_permission": len(detector_result.debugfs_permission_notes),
                "protected_mmu": len(detector_result.protected_mmu_notes),
                "active_singleton_stale": len(detector_result.active_singleton_stale_notes),
                "mmu_recovery": len(detector_result.mmu_recovery_notes),
                "sentinel_misuse": len(detector_result.sentinel_misuse_notes),
                "policy_gates": len(detector_result.policy_gate_notes),
                "imported_mapping_policy": len(detector_result.imported_mapping_policy_notes),
                "format_wrappers": len(detector_result.format_notes),
                "info_leaks": len(detector_result.info_leak_notes),
                "fops": len(detector_result.fops_notes),
                "lock_order": len(detector_result.lock_order_notes),
                "stale_after_unlock": len(detector_result.stale_after_unlock_notes),
                "disable_stale": len(detector_result.disable_stale_notes),
                "callback_lifetime": len(detector_result.callback_lifetime_notes),
                "cross_file_lock_cycles": len(detector_result.cross_file_lock_notes),
                "named_lock_inversion": len(detector_result.named_lock_inversion_notes),
                "protocol_candidates": len(detector_result.protocol_notes),
            })
            if detector_result.cross_file_lock_notes:
                progress_callback({
                    "event": "partial_lock_cycle_candidates",
                    "candidates": len(detector_result.cross_file_lock_notes),
                })
            if detector_result.protocol_notes:
                progress_callback({
                    "event": "partial_protocol_candidates",
                    "candidates": len(detector_result.protocol_notes),
                })
            exact_count = (
                len(detector_result.copy_contract_notes)
                + len(detector_result.cleanup_symmetry_notes)
                + len(detector_result.cleanup_ledger_notes)
                + len(detector_result.suspend_cleanup_ledger_notes)
                + len(detector_result.accounting_drift_notes)
                + len(detector_result.arithmetic_chain_notes)
                + len(detector_result.alias_extent_mismatch_notes)
                + len(detector_result.size_propagation_notes)
                + len(detector_result.suspend_size_sink_notes)
                + len(detector_result.resource_binding_notes)
                + len(detector_result.resource_validation_notes)
                + len(detector_result.async_order_notes)
                + len(detector_result.fault_clear_order_notes)
                + len(detector_result.stale_tracker_notes)
                + len(detector_result.region_replace_erase_notes)
                + len(detector_result.metadata_type_confusion_notes)
                + len(detector_result.pm_sequence_notes)
                + len(detector_result.pm_callback_order_notes)
                + len(detector_result.secondary_omission_notes)
                + len(detector_result.zero_count_underflow_notes)
                + len(detector_result.owner_liveness_notes)
                + len(detector_result.user_buffer_permission_notes)
                + len(detector_result.zone_shrink_notes)
                + len(detector_result.success_path_cleanup_notes)
                + len(detector_result.jit_lock_protocol_notes)
                + len(detector_result.teardown_order_notes)
                + len(detector_result.queue_publish_init_notes)
                + len(detector_result.fd_reuse_notes)
                + len(detector_result.debugfs_permission_notes)
                + len(detector_result.protected_mmu_notes)
                + len(detector_result.active_singleton_stale_notes)
                + len(detector_result.mmu_recovery_notes)
                + len(detector_result.sentinel_misuse_notes)
                + len(detector_result.policy_gate_notes)
                + len(detector_result.imported_mapping_policy_notes)
                + len(detector_result.named_lock_inversion_notes)
            )
            if exact_count:
                progress_callback({
                    "event": "partial_exact_root_cause_candidates",
                    "candidates": exact_count,
                })
        if progress_callback:
            progress_callback({
                "event": "partial_context_done",
                "target_nodes": len(context.target_nodes),
                "inbound": len(context.inbound_callers),
                "outbound": len(context.outbound_callees),
                "shared": len(context.shared_state_nodes),
                "lifecycle": len(context.lifecycle_pair_nodes),
                "callbacks": len(context.callback_nodes),
                "companions": len(context.companion_nodes),
                "total_selected": len(self._all_context_nodes(context)),
            })

        graph_builder = PartialGraphBuilder()
        partial_graph = graph_builder.build(context, index, self._config.codebase_path)
        context.candidate_paths = graph_builder.candidate_paths(context, partial_graph)
        if progress_callback:
            progress_callback({
                "event": "partial_graph_done",
                "nodes": partial_graph.node_count(),
                "edges": partial_graph.edge_count(),
                "paths": len(context.candidate_paths),
            })

        model = review_model or self._config.llama_query_model
        reviewer = TargetedFileReviewer(
            self._llm_provider, model, self._usage_runtime, self._config.codebase_path,
            cache=cache, symbol_index=index, reasoning_effort=reasoning_effort)
        findings = reviewer.review(
            context, partial_graph, detector_result=detector_result,
            max_workers=max_workers, progress_callback=progress_callback)
        review_errors = list(getattr(reviewer, "last_errors", []) or [])
        raw_findings = len(findings)
        findings = _post_filter_findings(findings, self._config.codebase_path)
        findings, filter_stats = _post_filter_partial_findings(
            findings, rel_target, detector_result, self._config.codebase_path)
        deduped = _dedupe_partial_findings(findings, max_per_sink=max_paths_per_sink)
        if progress_callback:
            progress_callback({
                "event": "partial_review_done",
                "raw_findings": raw_findings,
                "post_filtered_findings": len(findings),
                "deduped_findings": len(deduped),
                "suppressed_null": filter_stats.suppressed_null,
                "suppressed_lock": filter_stats.suppressed_lock,
                "suppressed_generic": filter_stats.suppressed_generic,
                "suppressed_non_target": filter_stats.suppressed_non_target,
            })
        result = {
            "file": rel_target,
            "file_path": abs_target,
            "reviews": [self._finding_to_review(f) for f in deduped],
        }
        if review_errors:
            result["errors"] = review_errors
        return result

    def _ensure_symbol_index(self, *, progress_callback=None):
        with self._index_lock:
            if self._symbol_index is not None:
                return self._symbol_index
            files = self._c_cpp_files()
            if progress_callback:
                progress_callback({"event": "partial_symbol_index_start", "files": len(files)})
            self._symbol_index = SymbolIndexBuilder().build(files, self._config.codebase_path)
            if progress_callback:
                progress_callback({
                    "event": "partial_symbol_index_done",
                    "files_indexed": self._symbol_index.files_indexed,
                    "definitions": sum(len(v) for v in self._symbol_index.definitions.values()),
                    "callsites": sum(len(v) for v in self._symbol_index.callsites.values()),
                    "fields": len(self._symbol_index.field_uses),
                    "locks": len(self._symbol_index.symbols_by_lock),
                    "state_tokens": len(self._symbol_index.symbols_by_state_token),
                    "event_tokens": len(self._symbol_index.symbols_by_event_token),
                    "globals": len(self._symbol_index.globals),
                })
            return self._symbol_index

    def _extract_target(self, abs_target, rel_target, extraction_model, max_workers, progress_callback, cache):
        if progress_callback:
            progress_callback({"event": "partial_target_extract_start", "file": rel_target})
        defs = _symbols_for_file(self._symbol_index, rel_target) if self._symbol_index is not None else []
        nodes = [
            _symbol_to_node(self._symbol_index, self._config.codebase_path, sym, cache)
            for sym in defs
        ]
        globals_ = (
            [g for g in self._symbol_index.globals if g.file_path == rel_target]
            if self._symbol_index is not None
            else []
        )
        if progress_callback:
            progress_callback({
                "event": "partial_target_extract_done",
                "file": rel_target,
                "target_nodes": len(nodes),
                "globals": len(globals_),
            })
        return nodes, globals_

    def _normalize_target_file(self, file_path):
        abs_target = _abs_path(str(file_path), self._config.codebase_path)
        rel_target = _rel_path(abs_target, self._config.codebase_path)
        return abs_target, rel_target

    def _c_cpp_files(self):
        return [
            f for f in self._repository.get_code_files()
            if os.path.splitext(f)[1].lower() in _C_CPP_EXTS
        ]

    def _merge_globals(self, a, b):
        seen = {}
        for g in list(a or []) + list(b or []):
            seen[g.unique_name] = g
        return list(seen.values())

    def _merge_detector_context(self, context: PartialReviewContext, detector_result: PartialDetectorResult):
        if detector_result.globals:
            context.globals = self._merge_globals(context.globals, detector_result.globals)
        if detector_result.nodes:
            context.lifecycle_pair_nodes = self._dedupe_nodes(
                list(context.lifecycle_pair_nodes or []) + list(detector_result.nodes))
        paths = list(context.candidate_paths or [])
        for target in context.target_nodes:
            for node in detector_result.nodes:
                if node.unique_name == target.unique_name:
                    continue
                if node.file_path == context.target_file:
                    continue
                paths.append(ReachabilityPath(
                    target.unique_name, node.unique_name,
                    [target.unique_name, node.unique_name],
                    node.sink_type,
                ))
        context.candidate_paths = _dedupe_paths(paths)

    def _dedupe_nodes(self, nodes: list[FunctionNode]) -> list[FunctionNode]:
        seen, out = set(), []
        for node in nodes:
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            out.append(node)
        return out

    def _all_context_nodes(self, context):
        seen = {}
        for group in (
            context.target_nodes, context.inbound_callers, context.outbound_callees,
            context.shared_state_nodes, context.lifecycle_pair_nodes,
            context.callback_nodes, context.companion_nodes,
        ):
            for node in group:
                seen[node.unique_name] = node
        return list(seen.values())

    def _filter_target_findings(self, findings, target_file):
        result = []
        for finding in findings:
            primary = finding.primary_file or finding.sink_file or finding.source_file
            if primary and _same_file_ref(primary, target_file, self._config.codebase_path):
                result.append(finding)
        return result

    def _finding_to_review(self, finding):
        line_number = int(finding.primary_line or finding.sink_line or finding.source_line or 1)
        vtype = _normalise_partial_vuln_type(finding.vulnerability_type)
        issue = str(finding.description).strip()
        if not issue:
            primary_fn = finding.primary_function or finding.sink_function
            issue = f"{vtype.replace('_', ' ')} in {primary_fn}"
        reasoning_parts = []
        if str(finding.evidence or "").strip():
            reasoning_parts.append(str(finding.evidence).strip())
        if finding.path:
            reasoning_parts.append(f"Reachability path: {' -> '.join(finding.path)}")
        if str(finding.root_cause or "").strip():
            reasoning_parts.append(f"Root cause: {str(finding.root_cause).strip()}")
        if finding.analysis_type:
            reasoning_parts.append(f"Analysis type: {finding.analysis_type}")
        if finding.canonical_key:
            reasoning_parts.append(f"Canonical key: {finding.canonical_key}")
        target_file = finding.primary_file or finding.sink_file or finding.source_file
        code_snippet = ""
        if target_file:
            code_snippet = _read_line_context(self._config.codebase_path, target_file, line_number, context=2)
        return {
            "issue": issue,
            "line_number": line_number,
            "code_snippet": code_snippet,
            "cwe": _partial_cwe(vtype, finding),
            "severity": _severity_title(finding.severity, "Medium"),
            "confidence": _confidence_score(finding.confidence),
            "reasoning": "\n".join(reasoning_parts),
            "mitigation": str(finding.root_cause or "").strip(),
        }

__all__ = [name for name in globals() if not name.startswith('__')]
