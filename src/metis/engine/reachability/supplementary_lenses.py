# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Supplementary reachability lens registry and prompt metadata."""

from __future__ import annotations

from dataclasses import dataclass

from .heuristic_data import _words


@dataclass(frozen=True)
class _SupplementaryLensSpec:
    name: str
    kind: str
    method_name: str = ""
    analysis_type: str = ""


_FULL_LENS_SPECS = (
    _SupplementaryLensSpec("intra_audit", "method", method_name="_lens_intra"),
    _SupplementaryLensSpec("lifecycle_audit", "cross", analysis_type="lifecycle"),
    _SupplementaryLensSpec("ownership_audit", "cross", analysis_type="ownership"),
    _SupplementaryLensSpec("semantic_audit", "semantic", analysis_type="semantic"),
    _SupplementaryLensSpec(
        "state_audit", "semantic", analysis_type="state_concurrency"
    ),
    _SupplementaryLensSpec(
        "targeted_state_order", "targeted", analysis_type="targeted_state_order"
    ),
    _SupplementaryLensSpec(
        "targeted_callback_lifecycle",
        "targeted",
        analysis_type="targeted_callback_lifecycle",
    ),
    _SupplementaryLensSpec(
        "targeted_refcount", "targeted", analysis_type="targeted_refcount"
    ),
    _SupplementaryLensSpec(
        "targeted_permission", "targeted", analysis_type="targeted_permission"
    ),
    _SupplementaryLensSpec(
        "targeted_toctou", "targeted", analysis_type="targeted_toctou"
    ),
    _SupplementaryLensSpec(
        "classic_c_sink",
        "candidate_intra",
        analysis_type="classic_c_sink",
    ),
    _SupplementaryLensSpec(
        "error_unwind",
        "candidate_semantic",
        analysis_type="error_unwind",
    ),
    _SupplementaryLensSpec(
        "counter_symmetry",
        "candidate_semantic",
        analysis_type="counter_symmetry",
    ),
    _SupplementaryLensSpec("global_lifecycle", "method", "_lens_global_lifecycle"),
    _SupplementaryLensSpec("lock_order_extraction", "method", "_lens_lock_order"),
    _SupplementaryLensSpec(
        "targeted_path_access",
        "candidate_semantic",
        analysis_type="targeted_path_access",
    ),
)

_REVIEW_LENS_NAMES = set(
    "intra_audit lifecycle_audit ownership_audit semantic_audit "
    "targeted_callback_lifecycle targeted_refcount targeted_permission "
    "classic_c_sink error_unwind counter_symmetry targeted_path_access".split()
)

_COMBINED_GRAPH_LENS_KINDS = _words("cross semantic targeted")
_COMBINED_GRAPH_LENS_NOTES = {
    "lifecycle": """\
analysis_type lifecycle:
- Report shown use-after-free, dangling/stale pointer, callback context lifetime,
  or realloc/grow invalidation bugs across functions.
- Require evidence that the resource lifetime ends before a later use.""",
    "ownership": """\
analysis_type ownership:
- Report ownership transfer mistakes, double release, refcount imbalance,
  missing cleanup symmetry, or rollback gaps.
- Require a concrete owner/releaser mismatch, not just unusual style.""",
    "semantic": """\
analysis_type semantic:
- Report wrong field/constant/domain, boolean coercion, type confusion,
  stale metadata, width/truncation, overflow/indexing, info leak, or missing auth.
- Prefer semantic correctness bugs with a shown bad consequence.""",
    "state_concurrency": """\
analysis_type state_concurrency:
- Report premature state flags, missing ordering before teardown/reset/power changes,
  stale-after-unlock, teardown races, missing locks, or lock inversions.
- Require shared mutable state or concurrent execution evidence.""",
    "targeted_state_order": """\
analysis_type targeted_state_order:
- Report only state/ready flag ordering bugs where a state is published before
  prerequisites complete and later trusted without rollback.""",
    "targeted_callback_lifecycle": """\
analysis_type targeted_callback_lifecycle:
- Report only callback teardown bugs where registered callback/work/timer context
  can outlive its object because cancel/flush/unregister is missing.""",
    "targeted_refcount": """\
analysis_type targeted_refcount:
- Report only no-op or imbalanced reference helpers that callers rely on for
  lifetime/accounting.""",
    "targeted_permission": """\
analysis_type targeted_permission:
- Report only missing privileged checks, wrong permission/resource/domain checks,
  or unsafe boolean coercion of roles/capabilities.""",
    "targeted_toctou": """\
analysis_type targeted_toctou:
- Report only filesystem check/use races where a path check is followed by open or
  mutation without an atomic/safe handle-based pattern.""",
    "error_unwind": """\
analysis_type error_unwind:
- Report partial cleanup, ownership overwrite, missing rollback after publish/register,
  ineffective cleanup helpers, or publication before initialization completes.
- Do not report borrowed fields as leaks unless ownership is shown.""",
    "counter_symmetry": """\
analysis_type counter_symmetry:
- Report counter/ref/accounting symmetry bugs: unmatched increments/decrements,
  stale deltas, never-updated counts, or no-op helpers trusted by callers.""",
    "targeted_path_access": """\
analysis_type targeted_path_access:
- Report caller-controlled filesystem paths used without canonicalization,
  base-directory restriction, or safe check/use discipline.
- Prefer path_traversal or toctou unless the root cause is authorization.""",
    "classic_c_sink": """\
analysis_type classic_c_sink:
- Report concrete misuse of dangerous C APIs: unbounded copies/formatting,
  oversized copies, allocation/copy overflow, attacker-controlled format strings,
  command injection, unsafe filesystem paths, TOCTOU, null deref, or OOB access.""",
    "global_lifecycle": """\
analysis_type global_lifecycle:
- Report lifecycle asymmetry in global operation/callback tables: missing
  unregister/cancel/flush/release when shared callbacks or references can outlive objects.""",
    "lock_order_extraction": """\
analysis_type lock_order_extraction:
- Confirm only feasible opposite lock acquisition orders on shared state.
- Ignore cases where locks are not held together or concurrency/lifecycle makes the
  order impossible.""",
}
