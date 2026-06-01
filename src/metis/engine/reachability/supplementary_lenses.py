# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from dataclasses import dataclass

from .supplementary_prompts import (
    _CLASSIC_C_SINK_SYS,
    _COUNTER_SYMMETRY_SYS,
    _ERROR_UNWIND_SYS,
    _TARGET_PATH_ACCESS_SYS,
)


@dataclass
class _SupplementaryLensSpec:
    name: str
    kind: str
    method_name: str = ""
    sys_prompt: str = ""
    analysis_type: str = ""
    max_total_chars: int = 0
    per_fn_chars: int = 0
    sinks_only: bool = False
    parser: str = "intra"

    def runs_as_combined_graph(self) -> bool:
        return self.kind in _COMBINED_GRAPH_LENS_KINDS

    def uses_method_runner(self) -> bool:
        return bool(self.method_name)

    def uses_candidate_runner(self) -> bool:
        return bool(self.sys_prompt)

    def parses_semantic_entries(self) -> bool:
        return self.parser == "semantic"


_PROMPTS = {
    "classic_c_sink": _CLASSIC_C_SINK_SYS,
    "error_unwind": _ERROR_UNWIND_SYS,
    "counter_symmetry": _COUNTER_SYMMETRY_SYS,
    "targeted_path_access": _TARGET_PATH_ACCESS_SYS,
}


def _lens_spec(name: str, kind: str, method: str, analysis_type: str):
    candidate_intra = kind == "candidate_intra"
    candidate_semantic = kind == "candidate_semantic"
    return _SupplementaryLensSpec(
        name,
        kind,
        method_name=method,
        sys_prompt=_PROMPTS.get(analysis_type, ""),
        analysis_type=analysis_type,
        max_total_chars=50000 if candidate_intra or candidate_semantic else 0,
        per_fn_chars=5000 if candidate_intra else 4000 if candidate_semantic else 0,
        sinks_only=analysis_type == "classic_c_sink",
        parser="semantic" if candidate_semantic else "intra",
    )


_FULL_LENS_SPECS = tuple(
    _lens_spec(name, kind, method, analysis_type)
    for name, kind, method, analysis_type in (
        ("intra_audit", "method", "_lens_intra", ""),
        ("lifecycle_audit", "cross", "", "lifecycle"),
        ("ownership_audit", "cross", "", "ownership"),
        ("semantic_audit", "semantic", "", "semantic"),
        ("state_audit", "semantic", "", "state_concurrency"),
        ("targeted_state_order", "targeted", "", "targeted_state_order"),
        ("targeted_callback_lifecycle", "targeted", "", "targeted_callback_lifecycle"),
        ("targeted_refcount", "targeted", "", "targeted_refcount"),
        ("targeted_permission", "targeted", "", "targeted_permission"),
        ("targeted_toctou", "targeted", "", "targeted_toctou"),
        ("classic_c_sink", "candidate_intra", "", "classic_c_sink"),
        ("error_unwind", "candidate_semantic", "", "error_unwind"),
        ("counter_symmetry", "candidate_semantic", "", "counter_symmetry"),
        ("global_lifecycle", "method", "_lens_global_lifecycle", ""),
        ("lock_order_extraction", "method", "_lens_lock_order", ""),
        ("targeted_path_access", "candidate_semantic", "", "targeted_path_access"),
    )
)

_REVIEW_LENS_NAMES = set(
    "intra_audit lifecycle_audit ownership_audit semantic_audit "
    "targeted_callback_lifecycle targeted_refcount targeted_permission "
    "classic_c_sink error_unwind counter_symmetry targeted_path_access".split()
)

_COMBINED_GRAPH_LENS_KINDS = frozenset("cross semantic targeted".split())
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
