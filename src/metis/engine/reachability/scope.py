# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Review scope records for reachability analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import ReachabilityPath, VulnerabilityFinding


@dataclass(frozen=True)
class ReachabilityReviewScope:
    """Concrete graph slice and path set to analyze for one review request."""

    scope_id: str
    analysis_graph: object
    finalizer_graph: object
    paths_to_confirm: list[ReachabilityPath] = field(default_factory=list)
    target_file: str = ""
    file_path: str = ""
    strict_file: bool = False
    lens_profile: str = "all"

    @property
    def is_file_review(self) -> bool:
        return bool(self.target_file)


@dataclass(frozen=True)
class ReachabilityScopeResult:
    findings: list[VulnerabilityFinding]
    total_before: int
    removed: int
    supplementary_count: int
    path_count: int
