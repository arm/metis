# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""LLM review passes for partial single-file reachability context."""

from __future__ import annotations

from .common import *

class TargetedFileReviewer:
    """Run focused prompts over target, related context, and detector notes."""

    def __init__(
        self,
        llm_provider,
        model,
        usage_runtime,
        codebase_path: str,
        max_tokens: int = 8192,
        cache: PartialAnalysisCache | None = None,
        symbol_index: SymbolIndex | None = None,
        reasoning_effort: str | None = None,
    ):
        self._p = llm_provider
        self._m = model
        self._u = usage_runtime
        self._cb = os.path.abspath(codebase_path)
        self._t = max_tokens
        self._cache = cache or PartialAnalysisCache(codebase_path, symbol_index)
        self._cache.bind_index(symbol_index)
        self._reasoning_effort = reasoning_effort

    def review(self, context: PartialReviewContext, partial_graph: ReachabilityGraph, *,
               detector_result: PartialDetectorResult | None = None,
               max_workers=4, progress_callback=None) -> list[VulnerabilityFinding]:
        detector_result = detector_result or PartialDetectorResult()
        passes = self._build_passes(context, partial_graph, detector_result)
        if not passes:
            return []
        if progress_callback:
            progress_callback({"event": "partial_review_start", "passes": len(passes)})
        findings: list[VulnerabilityFinding] = []
        self.last_errors = []
        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(passes)))) as ex:
            futs = {
                submit_with_current_context(ex, self._run_pass, context, partial_graph, item, detector_result): item[0]
                for item in passes
            }
            for fut in as_completed(futs):
                pass_name = futs[fut]
                try:
                    findings.extend(fut.result())
                except Exception as exc:
                    logger.warning("Partial review pass failed for %s: %s", pass_name, exc)
                    error = f"{pass_name}: {type(exc).__name__}: {exc}"
                    self.last_errors.append(error)
                    if progress_callback:
                        progress_callback({
                            "event": "partial_review_error",
                            "pass": pass_name,
                            "error": error,
                        })
        if progress_callback:
            progress_callback({"event": "partial_review_raw_done", "raw_findings": len(findings)})
        return findings

    def _build_passes(self, context, graph, detector_result):
        detector_nodes = detector_result.nodes or []
        copy_nodes = self._nodes_for_notes(detector_nodes, detector_result.copy_contract_notes)
        cleanup_nodes = self._nodes_for_notes(detector_nodes, detector_result.cleanup_symmetry_notes)
        accounting_nodes = self._nodes_for_notes(detector_nodes, detector_result.accounting_drift_notes)
        arithmetic_nodes = self._nodes_for_notes(detector_nodes, detector_result.arithmetic_chain_notes)
        resource_nodes = self._nodes_for_notes(detector_nodes, detector_result.resource_binding_notes)
        policy_nodes = self._nodes_for_notes(detector_nodes, detector_result.policy_gate_notes)
        resource_validation_nodes = self._nodes_for_notes(detector_nodes, detector_result.resource_validation_notes)
        cleanup_ledger_nodes = self._nodes_for_notes(detector_nodes, detector_result.cleanup_ledger_notes)
        async_nodes = self._nodes_for_notes(detector_nodes, detector_result.async_order_notes)
        size_nodes = self._nodes_for_notes(detector_nodes, detector_result.size_propagation_notes)
        tracker_nodes = self._nodes_for_notes(detector_nodes, detector_result.stale_tracker_notes)
        type_nodes = self._nodes_for_notes(detector_nodes, detector_result.metadata_type_confusion_notes)
        pm_nodes = self._nodes_for_notes(detector_nodes, detector_result.pm_sequence_notes)
        secondary_nodes = self._nodes_for_notes(detector_nodes, detector_result.secondary_omission_notes)
        protected_nodes = self._nodes_for_notes(detector_nodes, detector_result.protected_mmu_notes, cap=40)
        mmu_recovery_nodes = self._nodes_for_notes(detector_nodes, detector_result.mmu_recovery_notes, cap=32)
        sentinel_nodes = self._nodes_for_notes(detector_nodes, detector_result.sentinel_misuse_notes)
        suspend_cleanup_nodes = self._nodes_for_notes(detector_nodes, detector_result.suspend_cleanup_ledger_notes, cap=40)
        suspend_size_nodes = self._nodes_for_notes(detector_nodes, detector_result.suspend_size_sink_notes, cap=40)
        fault_clear_nodes = self._nodes_for_notes(detector_nodes, detector_result.fault_clear_order_notes, cap=40)
        pm_callback_nodes = self._nodes_for_notes(detector_nodes, detector_result.pm_callback_order_notes, cap=32)
        region_replace_nodes = self._nodes_for_notes(detector_nodes, detector_result.region_replace_erase_notes, cap=32)
        imported_mapping_nodes = self._nodes_for_notes(detector_nodes, detector_result.imported_mapping_policy_notes, cap=40)
        alias_extent_nodes = self._nodes_for_notes(detector_nodes, detector_result.alias_extent_mismatch_notes, cap=40)
        named_lock_nodes = self._nodes_for_notes(detector_nodes, detector_result.named_lock_inversion_notes, cap=48)
        active_singleton_nodes = self._nodes_for_notes(detector_nodes, detector_result.active_singleton_stale_notes, cap=40)
        zero_count_nodes = self._nodes_for_notes(detector_nodes, detector_result.zero_count_underflow_notes, cap=24)
        owner_liveness_nodes = self._nodes_for_notes(detector_nodes, detector_result.owner_liveness_notes, cap=32)
        user_buffer_nodes = self._nodes_for_notes(detector_nodes, detector_result.user_buffer_permission_notes, cap=32)
        zone_shrink_nodes = self._nodes_for_notes(detector_nodes, detector_result.zone_shrink_notes, cap=32)
        success_cleanup_nodes = self._nodes_for_notes(detector_nodes, detector_result.success_path_cleanup_notes, cap=32)
        jit_lock_nodes = self._nodes_for_notes(detector_nodes, detector_result.jit_lock_protocol_notes, cap=48)
        teardown_order_nodes = self._nodes_for_notes(detector_nodes, detector_result.teardown_order_notes, cap=48)
        queue_publish_nodes = self._nodes_for_notes(detector_nodes, detector_result.queue_publish_init_notes, cap=32)
        fd_reuse_nodes = self._nodes_for_notes(detector_nodes, detector_result.fd_reuse_notes, cap=32)
        debugfs_nodes = self._nodes_for_notes(detector_nodes, detector_result.debugfs_permission_notes, cap=32)
        lock_cycle_nodes = self._nodes_for_notes(detector_nodes, detector_result.cross_file_lock_notes, cap=48)
        protocol_nodes = self._nodes_for_notes(detector_nodes, detector_result.protocol_notes, cap=48)
        passes = [
            ("target_intra", context.target_nodes, []),
            ("inbound_contract", context.target_nodes, context.inbound_callers),
            ("outbound_misuse", context.target_nodes, context.outbound_callees),
            ("shared_state", context.target_nodes, context.shared_state_nodes),
            ("lifecycle", context.target_nodes, context.lifecycle_pair_nodes + context.callback_nodes),
            ("concurrency", context.target_nodes, context.shared_state_nodes + context.callback_nodes + context.lifecycle_pair_nodes),
        ]
        if detector_result.state_publication_notes or detector_result.disable_stale_notes:
            passes.append((
                "state_publication", context.target_nodes,
                context.shared_state_nodes + context.lifecycle_pair_nodes + context.callback_nodes + detector_nodes,
            ))
        if detector_result.publish_rollback_notes:
            passes.append(("publish_rollback", context.target_nodes, context.lifecycle_pair_nodes + detector_nodes))
        if detector_result.copy_contract_notes:
            passes.append(("copy_contract", context.target_nodes, copy_nodes))
        if detector_result.cleanup_symmetry_notes:
            passes.append(("cleanup_symmetry", context.target_nodes, context.lifecycle_pair_nodes + cleanup_nodes))
        if detector_result.accounting_drift_notes:
            passes.append(("accounting_drift", context.target_nodes, context.shared_state_nodes + accounting_nodes))
        if detector_result.cleanup_ledger_notes:
            passes.append(("cleanup_ledger", context.target_nodes, context.lifecycle_pair_nodes + context.companion_nodes + cleanup_ledger_nodes))
        if detector_result.suspend_cleanup_ledger_notes:
            passes.append(("suspend_cleanup_ledger", context.target_nodes, context.companion_nodes + suspend_cleanup_nodes))
        if detector_result.suspend_size_sink_notes:
            passes.append(("suspend_size_sink", context.target_nodes, context.outbound_callees + context.companion_nodes + suspend_size_nodes))
        if detector_result.resource_validation_notes:
            passes.append(("resource_validation_order", context.target_nodes, context.shared_state_nodes + context.companion_nodes + resource_validation_nodes))
        if detector_result.alias_extent_mismatch_notes:
            passes.append(("alias_extent_mismatch", context.target_nodes, context.outbound_callees + context.companion_nodes + alias_extent_nodes))
        if detector_result.arithmetic_chain_notes:
            passes.append(("arithmetic_chain_mismatch", context.target_nodes, context.outbound_callees + arithmetic_nodes))
        if detector_result.size_propagation_notes:
            passes.append(("size_propagation", context.target_nodes, context.outbound_callees + context.companion_nodes + size_nodes))
        if detector_result.resource_binding_notes:
            passes.append((
                "resource_binding_order", context.target_nodes,
                context.shared_state_nodes + context.lifecycle_pair_nodes + context.companion_nodes + resource_nodes,
            ))
        if detector_result.async_order_notes:
            passes.append(("async_event_order", context.target_nodes, context.callback_nodes + context.companion_nodes + async_nodes))
        if detector_result.fault_clear_order_notes:
            passes.append(("fault_clear_order", context.target_nodes, context.callback_nodes + context.companion_nodes + fault_clear_nodes))
        if detector_result.stale_tracker_notes:
            passes.append(("stale_tracker_state", context.target_nodes, context.shared_state_nodes + tracker_nodes))
        if detector_result.region_replace_erase_notes:
            passes.append(("region_replace_erase", context.target_nodes, context.shared_state_nodes + context.companion_nodes + region_replace_nodes))
        if detector_result.metadata_type_confusion_notes:
            passes.append(("metadata_type_confusion", context.target_nodes, type_nodes))
        if detector_result.pm_sequence_notes:
            passes.append(("pm_runtime_sequence", context.target_nodes, context.companion_nodes + pm_nodes))
        if detector_result.pm_callback_order_notes:
            passes.append(("pm_callback_order", context.target_nodes, context.companion_nodes + pm_callback_nodes))
        if detector_result.secondary_omission_notes:
            passes.append(("secondary_element_omission", context.target_nodes, secondary_nodes))
        if detector_result.zero_count_underflow_notes:
            passes.append(("zero_count_underflow", context.target_nodes, zero_count_nodes))
        if detector_result.owner_liveness_notes:
            passes.append(("owner_liveness_allocation", context.target_nodes, context.companion_nodes + owner_liveness_nodes))
        if detector_result.user_buffer_permission_notes:
            passes.append(("user_buffer_permission", context.target_nodes, context.companion_nodes + user_buffer_nodes))
        if detector_result.zone_shrink_notes:
            passes.append(("zone_shrink_validation", context.target_nodes, context.shared_state_nodes + context.companion_nodes + zone_shrink_nodes))
        if detector_result.success_path_cleanup_notes:
            passes.append(("success_path_cleanup", context.target_nodes, success_cleanup_nodes))
        if detector_result.jit_lock_protocol_notes:
            passes.append(("jit_lock_protocol", context.target_nodes, context.companion_nodes + context.shared_state_nodes + jit_lock_nodes))
        if detector_result.teardown_order_notes:
            passes.append(("teardown_order", context.target_nodes, context.companion_nodes + context.lifecycle_pair_nodes + teardown_order_nodes))
        if detector_result.queue_publish_init_notes:
            passes.append(("queue_publish_init", context.target_nodes, context.shared_state_nodes + queue_publish_nodes))
        if detector_result.fd_reuse_notes:
            passes.append(("fd_reuse_race", context.target_nodes, context.companion_nodes + fd_reuse_nodes))
        if detector_result.debugfs_permission_notes:
            passes.append(("debugfs_permission", context.target_nodes, debugfs_nodes))
        if detector_result.policy_gate_notes:
            passes.append((
                "policy_gate_before_sink", context.target_nodes,
                context.companion_nodes + context.outbound_callees + policy_nodes,
            ))
        if detector_result.imported_mapping_policy_notes:
            passes.append((
                "imported_mapping_policy", context.target_nodes,
                context.companion_nodes + context.outbound_callees + imported_mapping_nodes,
            ))
        if detector_result.sentinel_misuse_notes:
            passes.append(("sentinel_misuse", context.target_nodes, sentinel_nodes))
        if detector_result.mmu_recovery_notes:
            passes.append(("mmu_recovery_rollback", context.target_nodes, context.outbound_callees + mmu_recovery_nodes))
        if detector_result.allocation_arithmetic_notes:
            passes.append(("allocation_arithmetic", context.target_nodes, context.outbound_callees + detector_nodes))
        if detector_result.format_notes or detector_result.info_leak_notes:
            passes.append(("format_and_info_leak", context.target_nodes, context.outbound_callees + detector_nodes))
        if detector_result.fops_notes:
            passes.append(("fops_lifecycle", context.target_nodes, context.callback_nodes + context.lifecycle_pair_nodes + detector_nodes))
        if detector_result.lock_order_notes or detector_result.stale_after_unlock_notes:
            passes.append(("lock_and_stale", context.target_nodes, context.shared_state_nodes + context.lifecycle_pair_nodes + detector_nodes))
        if detector_result.cross_file_lock_notes:
            passes.append((
                "cross_file_lock_cycle", context.target_nodes,
                context.companion_nodes + context.callback_nodes + context.lifecycle_pair_nodes
                + context.shared_state_nodes + lock_cycle_nodes,
            ))
        if detector_result.named_lock_inversion_notes:
            passes.append((
                "named_lock_inversion", context.target_nodes,
                context.companion_nodes + context.callback_nodes + context.shared_state_nodes + named_lock_nodes,
            ))
        if detector_result.protocol_notes:
            passes.append((
                "state_transition_protocol", context.target_nodes,
                context.companion_nodes + context.lifecycle_pair_nodes + context.callback_nodes
                + context.shared_state_nodes + protocol_nodes,
            ))
        if detector_result.protected_mmu_notes:
            passes.append((
                "protected_mmu_protocol", context.target_nodes,
                context.companion_nodes + context.lifecycle_pair_nodes + context.callback_nodes + protected_nodes,
            ))
        if detector_result.active_singleton_stale_notes:
            passes.append((
                "active_singleton_stale", context.target_nodes,
                context.companion_nodes + context.lifecycle_pair_nodes + context.callback_nodes + active_singleton_nodes,
            ))
        if self._should_add_partial_exact_fallback(detector_result):
            fallback_nodes = (
                context.companion_nodes[:24] + context.shared_state_nodes[:24]
                + context.lifecycle_pair_nodes[:16] + context.outbound_callees[:16]
            )
            passes.append(("partial_exact_fallback", context.target_nodes, fallback_nodes))
        return passes

    def _should_add_partial_exact_fallback(self, detector_result: PartialDetectorResult) -> bool:
        strong = (
            detector_result.copy_contract_notes
            or detector_result.cleanup_symmetry_notes
            or detector_result.cleanup_ledger_notes
            or detector_result.suspend_cleanup_ledger_notes
            or detector_result.accounting_drift_notes
            or detector_result.arithmetic_chain_notes
            or detector_result.alias_extent_mismatch_notes
            or detector_result.size_propagation_notes
            or detector_result.suspend_size_sink_notes
            or detector_result.resource_binding_notes
            or detector_result.resource_validation_notes
            or detector_result.async_order_notes
            or detector_result.fault_clear_order_notes
            or detector_result.stale_tracker_notes
            or detector_result.region_replace_erase_notes
            or detector_result.metadata_type_confusion_notes
            or detector_result.pm_sequence_notes
            or detector_result.pm_callback_order_notes
            or detector_result.secondary_omission_notes
            or detector_result.zero_count_underflow_notes
            or detector_result.owner_liveness_notes
            or detector_result.user_buffer_permission_notes
            or detector_result.zone_shrink_notes
            or detector_result.success_path_cleanup_notes
            or detector_result.jit_lock_protocol_notes
            or detector_result.teardown_order_notes
            or detector_result.queue_publish_init_notes
            or detector_result.fd_reuse_notes
            or detector_result.debugfs_permission_notes
            or detector_result.policy_gate_notes
            or detector_result.imported_mapping_policy_notes
            or detector_result.sentinel_misuse_notes
            or detector_result.cross_file_lock_notes
            or detector_result.named_lock_inversion_notes
            or detector_result.protocol_notes
            or detector_result.protected_mmu_notes
            or detector_result.active_singleton_stale_notes
            or detector_result.mmu_recovery_notes
        )
        return not bool(strong)

    def _nodes_for_notes(self, nodes: list[FunctionNode], notes: list[str], *, cap: int = 32) -> list[FunctionNode]:
        if not nodes or not notes:
            return []
        text = "\n".join(notes[:80])
        selected = []
        seen = set()
        for node in nodes:
            keys = (node.unique_name, f"{node.file_path}::{node.name}", node.name)
            if not any(key and key in text for key in keys):
                continue
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            selected.append(node)
            if len(selected) >= cap:
                break
        if selected:
            return sorted(
                selected,
                key=lambda node: min(
                    (text.find(key) for key in (node.unique_name, f"{node.file_path}::{node.name}", node.name) if key and text.find(key) >= 0),
                    default=len(text),
                ),
            )
        return self._dedupe_nodes(nodes)[:cap]

    def _dedupe_nodes(self, nodes: list[FunctionNode]) -> list[FunctionNode]:
        seen, out = set(), []
        for node in nodes:
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            out.append(node)
        return out

    def _run_pass(self, context, graph, pass_item, detector_result):
        pass_name, target_nodes, context_nodes = pass_item
        target_code = self._build_code(target_nodes, per_fn_chars=4500, max_total_chars=42000)
        context_per_fn, context_total = self._context_code_budget(pass_name)
        context_code = self._build_code(context_nodes, per_fn_chars=context_per_fn, max_total_chars=context_total)
        if not target_code:
            return []
        prompt = ChatPromptTemplate.from_messages([
            ("system", _PARTIAL_REVIEW_SYS),
            ("user", _PARTIAL_REVIEW_USR),
        ])
        kw = self._u.hooks.chat_model_kwargs()
        if self._reasoning_effort and str(self._reasoning_effort).lower() not in {"none", "off", "false", "default"}:
            kw["reasoning_effort"] = self._reasoning_effort
        chat = self._p.get_chat_model(model=self._m, max_tokens=self._t, temperature=0.1, **kw)
        raw = (prompt | chat | StrOutputParser()).invoke({
            "target_file": context.target_file,
            "pass_name": pass_name,
            "focus": _PASS_FOCI[pass_name],
            "scope_rule": self._scope_rule_for_pass(pass_name, context.target_file),
            "paths_section": self._paths_section(context.candidate_paths, graph),
            "candidate_notes": self._candidate_notes_for_pass(pass_name, detector_result),
            "globals_section": self._globals_section(context.globals),
            "target_code": target_code,
            "context_code": context_code,
        }).strip()
        return self._parse_findings(raw, context, graph, analysis_type=f"partial_{pass_name}")

    def _context_code_budget(self, pass_name: str) -> tuple[int, int]:
        if pass_name in {
            "copy_contract", "cleanup_symmetry", "accounting_drift",
            "arithmetic_chain_mismatch", "resource_binding_order",
            "policy_gate_before_sink", "resource_validation_order",
            "cleanup_ledger", "async_event_order", "size_propagation",
            "stale_tracker_state", "metadata_type_confusion", "pm_runtime_sequence",
            "secondary_element_omission", "protected_mmu_protocol", "mmu_recovery_rollback",
            "sentinel_misuse", "suspend_cleanup_ledger", "suspend_size_sink",
            "fault_clear_order", "pm_callback_order", "region_replace_erase",
            "imported_mapping_policy", "alias_extent_mismatch", "named_lock_inversion",
            "active_singleton_stale", "zero_count_underflow", "owner_liveness_allocation",
            "user_buffer_permission", "zone_shrink_validation", "success_path_cleanup",
            "jit_lock_protocol", "teardown_order", "queue_publish_init", "fd_reuse_race",
            "debugfs_permission",
        }:
            return 2600, 36000
        if pass_name == "partial_exact_fallback":
            return 2800, 42000
        return 3000, 52000

    def _scope_rule_for_pass(self, pass_name: str, target_file: str) -> str:
        if pass_name in {"cross_file_lock_cycle", "state_transition_protocol"}:
            return (
                f"Findings must still use primary_file={target_file}. Companion files may prove the other half of the "
                "deadlock/protocol failure, but the target file must contain the concrete defective edge, unsafe transition, "
                "missing verification, or unsafe participation."
            )
        if pass_name in {
            "copy_contract", "cleanup_symmetry", "accounting_drift",
            "arithmetic_chain_mismatch", "resource_binding_order",
            "policy_gate_before_sink", "resource_validation_order",
            "cleanup_ledger", "async_event_order", "size_propagation",
            "stale_tracker_state", "metadata_type_confusion", "pm_runtime_sequence",
            "secondary_element_omission", "protected_mmu_protocol", "mmu_recovery_rollback",
            "sentinel_misuse", "suspend_cleanup_ledger", "suspend_size_sink",
            "fault_clear_order", "pm_callback_order", "region_replace_erase",
            "imported_mapping_policy", "alias_extent_mismatch", "named_lock_inversion",
            "active_singleton_stale", "zero_count_underflow", "owner_liveness_allocation",
            "user_buffer_permission", "zone_shrink_validation", "success_path_cleanup",
            "jit_lock_protocol", "teardown_order", "queue_publish_init", "fd_reuse_race",
            "debugfs_permission",
        }:
            return (
                f"Findings must use primary_file={target_file} and identify the exact target-file statement plus the exact "
                "missing check, missing rollback, mismatched formula, stale binding, missing serialization, wrong sentinel, "
                "bad cast, skipped second element, or missing policy gate. Do not report adjacent generic lifecycle/race/null/"
                "overflow/info-leak issues unless they are necessary to explain the same root cause."
            )
        if pass_name == "partial_exact_fallback":
            return (
                f"Findings must use primary_file={target_file}. This is a bounded recall fallback: report only concrete "
                "target-file root causes in ordering/race, cleanup/unwind, branch-specific release, size propagation, "
                "metadata reinterpretation, imported/SAME_VA policy, or sentinel misuse families. Do not report generic "
                "style, null, missing-lock, or adjacent helper issues."
            )
        return "Findings must be rooted in the target file. Other files are evidence/context only."

    def _build_code(self, nodes, *, per_fn_chars, max_total_chars):
        parts, total = [], 0
        seen = set()
        for node in sorted(nodes, key=lambda n: (n.file_path, n.line_number, n.name)):
            if node.unique_name in seen:
                continue
            seen.add(node.unique_name)
            body = self._cache.node_body(node, max_chars=per_fn_chars)
            if not body:
                continue
            entry = f"--- {node.unique_name} (line {node.line_number} in {node.file_path}) ---\n{body}"
            if total + len(entry) > max_total_chars and parts:
                break
            parts.append(entry)
            total += len(entry)
        return "\n\n".join(parts)

    def _paths_section(self, paths, graph):
        lines = []
        for i, path in enumerate(paths[:80]):
            lines.append(f"Path {i}: {' -> '.join(path.path)}")
        return "\n".join(lines) if lines else "(none)"

    def _globals_section(self, globals_):
        lines = []
        for g in globals_[:40]:
            refs = ", ".join(g.referenced_functions)
            lines.append(
                f"GLOBAL {g.unique_name} line {g.line_number} kind={g.kind}\n"
                f"refs: {refs}\n{g.initializer[:1600]}"
            )
        return "\n\n".join(lines) if lines else "(none)"

    def _candidate_notes_for_pass(self, pass_name: str, detector_result: PartialDetectorResult) -> str:
        mapping = {
            "state_publication": (
                ("STATE_PUBLICATION", detector_result.state_publication_notes),
                ("DISABLE_STALE", detector_result.disable_stale_notes),
            ),
            "publish_rollback": (("PUBLISH_ROLLBACK", detector_result.publish_rollback_notes),),
            "allocation_arithmetic": (("ALLOCATION_ARITHMETIC", detector_result.allocation_arithmetic_notes),),
            "copy_contract": (("COPY_CONTRACT", detector_result.copy_contract_notes),),
            "cleanup_symmetry": (("CLEANUP_SYMMETRY", detector_result.cleanup_symmetry_notes),),
            "accounting_drift": (("ACCOUNTING_DRIFT", detector_result.accounting_drift_notes),),
            "cleanup_ledger": (("CLEANUP_LEDGER", detector_result.cleanup_ledger_notes),),
            "suspend_cleanup_ledger": (
                ("SUSPEND_CLEANUP_LEDGER", detector_result.suspend_cleanup_ledger_notes),
                ("CLEANUP_LEDGER", detector_result.cleanup_ledger_notes[:8]),
            ),
            "suspend_size_sink": (
                ("SUSPEND_SIZE_SINK", detector_result.suspend_size_sink_notes),
                ("SIZE_PROPAGATION", detector_result.size_propagation_notes[:8]),
            ),
            "resource_validation_order": (("RESOURCE_VALIDATION_ORDER", detector_result.resource_validation_notes),),
            "arithmetic_chain_mismatch": (
                ("ARITHMETIC_CHAIN_MISMATCH", detector_result.arithmetic_chain_notes),
                ("ALLOCATION_ARITHMETIC", detector_result.allocation_arithmetic_notes[:12]),
            ),
            "alias_extent_mismatch": (
                ("ALIAS_EXTENT_MISMATCH", detector_result.alias_extent_mismatch_notes),
                ("ARITHMETIC_CHAIN_MISMATCH", detector_result.arithmetic_chain_notes[:8]),
            ),
            "size_propagation": (
                ("SIZE_PROPAGATION", detector_result.size_propagation_notes),
                ("ARITHMETIC_CHAIN_MISMATCH", detector_result.arithmetic_chain_notes[:12]),
            ),
            "resource_binding_order": (
                ("RESOURCE_BINDING_ORDER", detector_result.resource_binding_notes),
                ("RESOURCE_VALIDATION_ORDER", detector_result.resource_validation_notes[:12]),
                ("STATE_PUBLICATION", detector_result.state_publication_notes[:12]),
                ("DISABLE_STALE", detector_result.disable_stale_notes[:12]),
            ),
            "async_event_order": (("ASYNC_EVENT_ORDER", detector_result.async_order_notes),),
            "fault_clear_order": (
                ("FAULT_CLEAR_ORDER", detector_result.fault_clear_order_notes),
                ("ASYNC_EVENT_ORDER", detector_result.async_order_notes[:8]),
            ),
            "stale_tracker_state": (("STALE_TRACKER_STATE", detector_result.stale_tracker_notes),),
            "region_replace_erase": (
                ("REGION_REPLACE_ERASE", detector_result.region_replace_erase_notes),
                ("STALE_TRACKER_STATE", detector_result.stale_tracker_notes[:8]),
            ),
            "metadata_type_confusion": (("METADATA_TYPE_CONFUSION", detector_result.metadata_type_confusion_notes),),
            "pm_runtime_sequence": (("PM_RUNTIME_SEQUENCE", detector_result.pm_sequence_notes),),
            "pm_callback_order": (
                ("PM_CALLBACK_ORDER", detector_result.pm_callback_order_notes),
                ("PM_RUNTIME_SEQUENCE", detector_result.pm_sequence_notes[:8]),
            ),
            "secondary_element_omission": (("SECONDARY_ELEMENT_OMISSION", detector_result.secondary_omission_notes),),
            "zero_count_underflow": (("ZERO_COUNT_UNDERFLOW", detector_result.zero_count_underflow_notes),),
            "owner_liveness_allocation": (("OWNER_LIVENESS_ALLOCATION", detector_result.owner_liveness_notes),),
            "user_buffer_permission": (("USER_BUFFER_PERMISSION", detector_result.user_buffer_permission_notes),),
            "zone_shrink_validation": (("ZONE_SHRINK_VALIDATION", detector_result.zone_shrink_notes),),
            "success_path_cleanup": (
                ("SUCCESS_PATH_CLEANUP", detector_result.success_path_cleanup_notes),
                ("CLEANUP_SYMMETRY", detector_result.cleanup_symmetry_notes[:6]),
            ),
            "jit_lock_protocol": (("JIT_LOCK_PROTOCOL", detector_result.jit_lock_protocol_notes),),
            "teardown_order": (("TEARDOWN_ORDER", detector_result.teardown_order_notes),),
            "queue_publish_init": (
                ("QUEUE_PUBLISH_INIT", detector_result.queue_publish_init_notes),
                ("STATE_PUBLICATION", detector_result.state_publication_notes[:6]),
            ),
            "fd_reuse_race": (("FD_REUSE_RACE", detector_result.fd_reuse_notes),),
            "debugfs_permission": (("DEBUGFS_PERMISSION", detector_result.debugfs_permission_notes),),
            "protected_mmu_protocol": (
                ("PROTECTED_MMU_PROTOCOL", detector_result.protected_mmu_notes),
                ("STATE_TRANSITION_PROTOCOL", detector_result.protocol_notes[:12]),
            ),
            "active_singleton_stale": (
                ("ACTIVE_SINGLETON_STALE", detector_result.active_singleton_stale_notes),
                ("PROTECTED_MMU_PROTOCOL", detector_result.protected_mmu_notes[:8]),
            ),
            "mmu_recovery_rollback": (("MMU_RECOVERY_ROLLBACK", detector_result.mmu_recovery_notes),),
            "sentinel_misuse": (("SENTINEL_MISUSE", detector_result.sentinel_misuse_notes),),
            "policy_gate_before_sink": (("POLICY_GATE_BEFORE_SINK", detector_result.policy_gate_notes),),
            "imported_mapping_policy": (
                ("IMPORTED_MAPPING_POLICY", detector_result.imported_mapping_policy_notes),
                ("POLICY_GATE_BEFORE_SINK", detector_result.policy_gate_notes[:8]),
            ),
            "format_and_info_leak": (
                ("FORMAT_WRAPPER", detector_result.format_notes),
                ("INFO_LEAK", detector_result.info_leak_notes),
            ),
            "fops_lifecycle": (
                ("FOPS_LIFECYCLE", detector_result.fops_notes),
                ("CALLBACK_LIFETIME", detector_result.callback_lifetime_notes),
            ),
            "lock_and_stale": (
                ("LOCK_ORDER", detector_result.lock_order_notes),
                ("STALE_AFTER_UNLOCK", detector_result.stale_after_unlock_notes),
            ),
            "cross_file_lock_cycle": (
                ("CROSS_FILE_LOCK_CYCLE", detector_result.cross_file_lock_notes),
                ("LOCK_ORDER", detector_result.lock_order_notes[:20]),
            ),
            "named_lock_inversion": (
                ("NAMED_LOCK_INVERSION", detector_result.named_lock_inversion_notes),
                ("CROSS_FILE_LOCK_CYCLE", detector_result.cross_file_lock_notes[:8]),
            ),
            "state_transition_protocol": (
                ("STATE_TRANSITION_PROTOCOL", detector_result.protocol_notes),
                ("STATE_PUBLICATION", detector_result.state_publication_notes[:20]),
                ("DISABLE_STALE", detector_result.disable_stale_notes[:20]),
            ),
            "lifecycle": (
                ("CALLBACK_LIFETIME", detector_result.callback_lifetime_notes[:20]),
                ("FOPS_LIFECYCLE", detector_result.fops_notes[:20]),
            ),
            "concurrency": (
                ("LOCK_ORDER", detector_result.lock_order_notes[:20]),
                ("STALE_AFTER_UNLOCK", detector_result.stale_after_unlock_notes[:20]),
            ),
            "target_intra": (
                ("STATE_PUBLICATION", detector_result.state_publication_notes[:12]),
                ("ALLOCATION_ARITHMETIC", detector_result.allocation_arithmetic_notes[:12]),
                ("FORMAT_OR_INFO", (detector_result.format_notes + detector_result.info_leak_notes)[:12]),
            ),
            "shared_state": (
                ("DISABLE_STALE", detector_result.disable_stale_notes[:12]),
                ("CALLBACK_LIFETIME", detector_result.callback_lifetime_notes[:12]),
            ),
            "partial_exact_fallback": (
                ("STATE_PUBLICATION", detector_result.state_publication_notes[:8]),
                ("PUBLISH_ROLLBACK", detector_result.publish_rollback_notes[:8]),
                ("LOCK_ORDER", detector_result.lock_order_notes[:8]),
                ("CALLBACK_LIFETIME", detector_result.callback_lifetime_notes[:8]),
            ),
        }
        groups = mapping.get(pass_name, ())
        lines: list[str] = []
        for title, notes in groups:
            if not notes:
                continue
            lines.append(f"{title}:")
            lines.extend(f"- {note}" for note in notes[:40])
        if len(lines) > 90:
            lines = lines[:90] + ["- ..."]
        return "\n".join(lines) if lines else "(none)"

    def _parse_findings(self, raw, context, graph, analysis_type):
        parsed = parse_json_output(raw)
        if not isinstance(parsed, dict):
            return []
        entries = parsed.get("findings")
        if not isinstance(entries, list):
            return []
        by_name = {n.name: n for n in graph.nodes.values()}
        by_unique = dict(graph.nodes)
        target_default = context.target_nodes[0] if context.target_nodes else None
        results = []
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("is_vulnerable") is False:
                continue
            fn = self._lookup_node(str(entry.get("function_name") or ""), by_name, by_unique) or target_default
            related = self._lookup_node(str(entry.get("related_function") or ""), by_name, by_unique)
            if not fn:
                continue
            line = _safe_int(entry.get("line"), fn.line_number)
            primary_file = str(entry.get("primary_file") or "").strip() or fn.file_path
            primary_function = str(entry.get("primary_function") or "").strip() or fn.unique_name
            primary_line = _safe_int(entry.get("primary_line"), line)
            canonical_key = str(entry.get("canonical_key") or "").strip()
            if not _same_file_ref(primary_file, context.target_file, self._cb):
                continue
            src = related or fn
            results.append(VulnerabilityFinding(
                id=os.urandom(8).hex(),
                vulnerability_type=_normalise_partial_vuln_type(entry.get("vulnerability_type") or "other"),
                severity=str(entry.get("severity") or "medium"),
                confidence=str(entry.get("confidence") or "medium"),
                source_function=src.unique_name,
                source_file=src.file_path,
                source_line=src.line_number,
                sink_function=fn.unique_name,
                sink_file=fn.file_path,
                sink_line=line,
                path=[src.unique_name, fn.unique_name] if related else [fn.unique_name],
                description=str(entry.get("description") or ""),
                root_cause=str(entry.get("root_cause") or ""),
                evidence=str(entry.get("evidence") or ""),
                analysis_type=analysis_type,
                primary_file=primary_file,
                primary_function=primary_function,
                primary_line=primary_line,
                canonical_key=canonical_key,
            ))
        return results

    def _lookup_node(self, name, by_name, by_unique):
        if not name:
            return None
        if name in by_unique:
            return by_unique[name]
        if name in by_name:
            return by_name[name]
        short = name.split("::")[-1]
        return by_name.get(short)



__all__ = [name for name in globals() if not name.startswith('__')]
