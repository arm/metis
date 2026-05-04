# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from .common import *

def _partial_finding_text(finding: VulnerabilityFinding) -> str:
    return " ".join(str(part or "") for part in (
        finding.description, finding.root_cause, finding.evidence, finding.canonical_key,
        finding.primary_function, finding.sink_function, finding.source_function,
    ))


def _partial_duplicate_family(vtype: str) -> str:
    normal = _normalise_partial_vuln_type(vtype)
    aliases = {
        "callback_lifecycle": "teardown_lifecycle",
        "deferred_uaf": "teardown_lifecycle",
        "teardown_race": "teardown_lifecycle",
        "file_ops_lifecycle_gap": "teardown_lifecycle",
        "stale_after_unlock": "lifetime",
        "stale_pointer": "lifetime",
        "use_after_free": "lifetime",
        "refcount_imbalance": "accounting",
        "wrong_constant": "semantic_mismatch",
        "wrong_flag_semantic": "semantic_mismatch",
        "permission_mismatch": "semantic_mismatch",
        "state_order": "state_order",
        "ordering_gap": "state_order",
        "stale_state": "state_order",
        "copy_contract": "copy_contract",
        "cleanup_symmetry": "cleanup",
        "accounting_drift": "accounting",
        "arithmetic_chain_mismatch": "arithmetic_chain",
        "resource_binding_order": "resource_binding",
        "policy_gate_before_sink": "policy_gate",
        "cross_file_lock_cycle": "lock_cycle",
        "state_transition_protocol": "state_order",
        "resource_validation_order": "resource_binding",
        "cleanup_ledger": "cleanup",
        "suspend_cleanup_ledger": "cleanup",
        "suspend_size_sink": "arithmetic_chain",
        "async_event_order": "state_order",
        "fault_clear_order": "state_order",
        "size_propagation": "arithmetic_chain",
        "alias_extent_mismatch": "arithmetic_chain",
        "stale_tracker_state": "resource_binding",
        "region_replace_erase": "resource_binding",
        "metadata_type_confusion": "type_confusion",
        "pm_runtime_sequence": "state_order",
        "pm_callback_order": "state_order",
        "secondary_element_omission": "logic_omission",
        "zero_count_underflow": "integer_underflow",
        "owner_liveness_allocation": "resource_exhaustion",
        "user_buffer_permission": "policy_gate",
        "zone_shrink_validation": "resource_binding",
        "success_path_cleanup": "cleanup",
        "jit_lock_protocol": "lock_cycle",
        "teardown_order": "lifetime",
        "queue_publish_init": "lifetime",
        "fd_reuse_race": "lifetime",
        "debugfs_permission": "policy_gate",
        "protected_mmu_protocol": "state_order",
        "active_singleton_stale": "lifetime",
        "mmu_recovery_rollback": "mmu_recovery",
        "sentinel_misuse": "semantic_mismatch",
        "imported_mapping_policy": "policy_gate",
        "named_lock_inversion": "lock_cycle",
    }
    return aliases.get(normal, normal)


def _partial_canonical_key(key: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", str(key or "").lower())
    noisy = {
        "unchecked", "direct", "same", "path", "same_path", "same_path_input",
        "input", "user", "attacker", "unsanitized", "untrusted", "source", "sink",
    }
    tokens = [t for t in text.split("_") if t and t not in noisy]
    return "_".join(tokens)


def _partial_overlap(a: VulnerabilityFinding, b: VulnerabilityFinding) -> float:
    ta = _partial_note_tokens(_partial_finding_text(a))
    tb = _partial_note_tokens(_partial_finding_text(b))
    if not ta or not tb:
        return 0.0
    common = len(ta & tb)
    return common / max(1, min(len(ta), len(tb)))


def _partial_same_root(a: VulnerabilityFinding, b: VulnerabilityFinding) -> bool:
    af = a.primary_file or a.sink_file or a.source_file
    bf = b.primary_file or b.sink_file or b.source_file
    if af != bf:
        return False
    family_a = _partial_duplicate_family(a.vulnerability_type)
    family_b = _partial_duplicate_family(b.vulnerability_type)
    if family_a != family_b:
        return False
    fn_a = a.primary_function or a.sink_function or a.source_function
    fn_b = b.primary_function or b.sink_function or b.source_function
    line_a = _safe_int(a.primary_line or a.sink_line or a.source_line, 0)
    line_b = _safe_int(b.primary_line or b.sink_line or b.source_line, 0)
    if fn_a == fn_b and line_a and line_b and abs(line_a - line_b) <= 10:
        return True
    if a.sink_line and b.sink_line and a.sink_line == b.sink_line:
        return True
    ca = _partial_canonical_key(a.canonical_key)
    cb = _partial_canonical_key(b.canonical_key)
    if ca and cb and ca == cb:
        return True
    return fn_a == fn_b and _partial_overlap(a, b) >= 0.58


def _pick_partial_best(findings: list[VulnerabilityFinding]) -> VulnerabilityFinding:
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    conf = {"high": 0, "medium": 1, "low": 2}
    return min(findings, key=lambda f: (
        _PARTIAL_PASS_PRIORITY.get(f.analysis_type, 50),
        sev.get(str(f.severity or "").lower(), 5),
        conf.get(str(f.confidence or "").lower(), 3),
        len(f.path or []),
        -len(_partial_finding_text(f)),
    ))


def _collapse_partial_duplicates(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    clusters: list[list[VulnerabilityFinding]] = []
    for finding in findings:
        merged = False
        for cluster in clusters:
            if _partial_same_root(finding, cluster[0]):
                cluster.append(finding)
                merged = True
                break
        if not merged:
            clusters.append([finding])
    return [_pick_partial_best(cluster) for cluster in clusters]


def _dedupe_partial_findings(findings: list[VulnerabilityFinding], *, max_per_sink: int) -> list[VulnerabilityFinding]:
    collapsed = _collapse_partial_duplicates(findings)
    deduped, _, _ = Deduplicator.deduplicate(collapsed, max_per_sink=max_per_sink)
    return _collapse_partial_duplicates(deduped)


def _is_external_entrypoint_finding(finding: VulnerabilityFinding) -> bool:
    text = _partial_finding_text(finding).lower()
    fn = str(finding.primary_function or finding.sink_function or finding.source_function or "").lower()
    return bool(re.search(
        r"\b(ioctl|dispatch|sysfs|debugfs|netlink|fops|file_operations|open|read|write|"
        r"poll|flush|release|callback|handler|irq|interrupt|user|copy_from_user|main)\b",
        f"{fn} {text}",
    ))


def _suppress_generic_null(finding: VulnerabilityFinding) -> bool:
    if _normalise_partial_vuln_type(finding.vulnerability_type) != "null_deref":
        return False
    text = _partial_finding_text(finding).lower()
    if re.search(r"\b(lookup|find|malloc|calloc|realloc|returns?\s+null|no matching|after loop|task_find|session_get|store_get|get_)\b", text):
        return False
    if _is_external_entrypoint_finding(finding):
        return False
    return bool(re.search(
        r"(missing\s+null\s+check|missing\s+null-check|caller-supplied pointer|"
        r"inbound pointer contract|missing validation of .* pointer|missing null check on "
        r"(?:dev|ctx|queue|obj|session|task|region))",
        text,
    ))


def _suppress_generic_missing_lock(finding: VulnerabilityFinding, detector_result: PartialDetectorResult) -> bool:
    if _normalise_partial_vuln_type(finding.vulnerability_type) != "missing_lock":
        return False
    text = _partial_finding_text(finding).lower()
    concrete = re.search(r"\b(free|destroy|teardown|release|callback|work|timer|fops|poll|ioctl|use-after-free|uaf|corrupt)\b", text)
    if concrete:
        return False
    notes = " ".join(
        detector_result.lock_order_notes
        + detector_result.stale_after_unlock_notes
        + detector_result.callback_lifetime_notes
        + detector_result.fops_notes
    )
    if _partial_note_tokens(text) & _partial_note_tokens(notes):
        return False
    return True


def _suppress_generic_partial(finding: VulnerabilityFinding) -> bool:
    text = _partial_finding_text(finding).lower()
    severity = str(finding.severity or "").lower()
    vtype = _normalise_partial_vuln_type(finding.vulnerability_type)
    if ("overwrites global file handle" in text or "repeated init" in text) and severity not in {"high", "critical"}:
        if not re.search(r"\b(double|use-after-free|uaf|security|attacker|external)\b", text):
            return True
    if vtype in {"missing_auth", "permission_mismatch"} and not _is_external_entrypoint_finding(finding):
        if re.search(r"\b(primitive|helper|low-level|lacks built-in authorization|caller authorization)\b", text):
            return True
    return False


_EXACT_PARTIAL_ANALYSIS_TYPES = frozenset({
    "partial_copy_contract",
    "partial_cleanup_symmetry",
    "partial_accounting_drift",
    "partial_arithmetic_chain_mismatch",
    "partial_resource_binding_order",
    "partial_policy_gate_before_sink",
    "partial_cross_file_lock_cycle",
    "partial_state_transition_protocol",
    "partial_resource_validation_order",
    "partial_cleanup_ledger",
    "partial_suspend_cleanup_ledger",
    "partial_suspend_size_sink",
    "partial_async_event_order",
    "partial_fault_clear_order",
    "partial_size_propagation",
    "partial_alias_extent_mismatch",
    "partial_stale_tracker_state",
    "partial_region_replace_erase",
    "partial_metadata_type_confusion",
    "partial_pm_runtime_sequence",
    "partial_pm_callback_order",
    "partial_secondary_element_omission",
    "partial_zero_count_underflow",
    "partial_owner_liveness_allocation",
    "partial_user_buffer_permission",
    "partial_zone_shrink_validation",
    "partial_success_path_cleanup",
    "partial_jit_lock_protocol",
    "partial_teardown_order",
    "partial_queue_publish_init",
    "partial_fd_reuse_race",
    "partial_debugfs_permission",
    "partial_protected_mmu_protocol",
    "partial_active_singleton_stale",
    "partial_mmu_recovery_rollback",
    "partial_sentinel_misuse",
    "partial_imported_mapping_policy",
    "partial_named_lock_inversion",
})
_WEAK_GENERIC_VTYPES = frozenset({
    "null_deref", "missing_lock", "teardown_race", "callback_lifecycle",
    "deferred_uaf", "integer_overflow", "buffer_overflow", "lock_order",
    "state_order", "ordering_gap", "info_leak", "format_string", "other",
})


def _prefer_exact_partial_findings(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    exact = [f for f in findings if f.analysis_type in _EXACT_PARTIAL_ANALYSIS_TYPES]
    if not exact:
        return findings
    kept = []
    for finding in findings:
        if finding.analysis_type in _EXACT_PARTIAL_ANALYSIS_TYPES:
            if _is_weaker_exact_adjacent_to_stronger(finding, exact):
                continue
            kept.append(finding)
            continue
        if not _is_weaker_adjacent_to_exact(finding, exact):
            kept.append(finding)
    return kept


def _is_weaker_exact_adjacent_to_stronger(finding: VulnerabilityFinding, exact_findings: list[VulnerabilityFinding]) -> bool:
    weaker = {
        "partial_cross_file_lock_cycle", "partial_state_transition_protocol",
        "partial_resource_binding_order", "partial_allocation_arithmetic",
        "partial_async_event_order", "partial_cleanup_ledger",
        "partial_arithmetic_chain_mismatch", "partial_size_propagation",
        "partial_policy_gate_before_sink", "partial_stale_tracker_state",
        "partial_pm_runtime_sequence",
    }
    if finding.analysis_type not in weaker:
        return False
    own_priority = _PARTIAL_PASS_PRIORITY.get(finding.analysis_type, 50)
    fn = finding.primary_function or finding.sink_function or finding.source_function
    line = _safe_int(finding.primary_line or finding.sink_line or finding.source_line, 0)
    text = _partial_finding_text(finding).lower()
    finding_file = finding.primary_file or finding.sink_file or finding.source_file
    finding_domains = _domain_root_tokens(text)
    for exact in exact_findings:
        if exact is finding:
            continue
        if _PARTIAL_PASS_PRIORITY.get(exact.analysis_type, 50) >= own_priority:
            continue
        exact_file = exact.primary_file or exact.sink_file or exact.source_file
        if finding_file and exact_file and finding_file != exact_file:
            continue
        exact_fn = exact.primary_function or exact.sink_function or exact.source_function
        exact_line = _safe_int(exact.primary_line or exact.sink_line or exact.source_line, 0)
        exact_text = _partial_finding_text(exact).lower()
        exact_domains = _domain_root_tokens(exact_text)
        if not (finding_domains & exact_domains):
            continue
        same_fn = bool(fn and exact_fn and fn == exact_fn)
        tight_line = bool(line and exact_line and abs(line - exact_line) <= 10)
        if same_fn or tight_line:
            return True
    return False


def _is_weaker_adjacent_to_exact(finding: VulnerabilityFinding, exact_findings: list[VulnerabilityFinding]) -> bool:
    vtype = _normalise_partial_vuln_type(finding.vulnerability_type)
    if vtype not in _WEAK_GENERIC_VTYPES and not finding.analysis_type.endswith(("target_intra", "concurrency", "lifecycle")):
        return False
    fn = finding.primary_function or finding.sink_function or finding.source_function
    line = _safe_int(finding.primary_line or finding.sink_line or finding.source_line, 0)
    weak_text = _partial_finding_text(finding).lower()
    weak_domains = _domain_root_tokens(weak_text)
    finding_file = finding.primary_file or finding.sink_file or finding.source_file
    for exact in exact_findings:
        exact_file = exact.primary_file or exact.sink_file or exact.source_file
        if finding_file and exact_file and finding_file != exact_file:
            continue
        exact_text = _partial_finding_text(exact).lower()
        exact_domains = _domain_root_tokens(exact_text)
        if not (weak_domains & exact_domains):
            continue
        exact_fn = exact.primary_function or exact.sink_function or exact.source_function
        exact_line = _safe_int(exact.primary_line or exact.sink_line or exact.source_line, 0)
        same_fn = bool(fn and exact_fn and fn == exact_fn)
        tight_line = bool(
            (line and exact_line and abs(line - exact_line) <= 10)
            or (exact.sink_line and finding.sink_line and abs(exact.sink_line - finding.sink_line) <= 10)
        )
        if same_fn or tight_line:
            return True
    return False


def _post_filter_partial_findings(
    findings: list[VulnerabilityFinding],
    target_file: str,
    detector_result: PartialDetectorResult,
    codebase_path: str,
) -> tuple[list[VulnerabilityFinding], PartialPostFilterStats]:
    stats = PartialPostFilterStats()
    kept: list[VulnerabilityFinding] = []
    for finding in findings:
        finding.vulnerability_type = _normalise_partial_vuln_type(finding.vulnerability_type)
        primary = finding.primary_file or finding.sink_file or finding.source_file
        if not primary or not _same_file_ref(primary, target_file, codebase_path):
            stats.suppressed_non_target += 1
            continue
        if _suppress_generic_null(finding):
            stats.suppressed_null += 1
            continue
        if _suppress_generic_missing_lock(finding, detector_result):
            stats.suppressed_lock += 1
            continue
        if _suppress_generic_partial(finding):
            stats.suppressed_generic += 1
            continue
        kept.append(finding)
    refined = _prefer_exact_partial_findings(kept)
    stats.suppressed_generic += len(kept) - len(refined)
    return refined, stats


def _partial_cwe(vtype: str, finding: VulnerabilityFinding) -> str | None:
    normal = _normalise_partial_vuln_type(vtype)
    if normal == "info_leak":
        text = _partial_finding_text(finding).lower()
        return "CWE-532" if re.search(r"\b(log|printf|debug|trace|printk)\b", text) else "CWE-200"
    return _PARTIAL_CWE_OVERRIDES.get(normal) or _VULN_TO_CWE.get(normal)



__all__ = [name for name in globals() if not name.startswith('__')]
