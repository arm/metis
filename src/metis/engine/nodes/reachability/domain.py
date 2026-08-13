# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from typing import Literal

FrontierReviewFailureKind = Literal[
    "missing_source",
    "context_overflow",
    "invalid_output",
    "provider_error",
]


@dataclass(frozen=True, slots=True)
class FrontierReviewFailure:
    function_id: str
    kind: FrontierReviewFailureKind


@dataclass
class ReachabilityPath:
    source: str
    sink: str
    path: list[str] = field(default_factory=list)
    sink_type: str = ""


@dataclass
class VulnerabilityFinding:
    id: str
    vulnerability_type: str
    severity: str
    confidence: float
    source_function: str
    source_file: str
    source_line: int
    sink_function: str
    sink_file: str
    sink_line: int
    path: list[str] = field(default_factory=list)
    description: str = ""
    root_cause: str = ""
    evidence: str = ""
    mitigation: str = ""
    cwe: str = ""
    analysis_type: str = "reachability"
    primary_file: str = ""
    primary_function: str = ""
    primary_line: int = 0
    canonical_key: str = ""
    primary_anchor: dict | None = None

    def __post_init__(self) -> None:
        if not self.primary_file:
            self.primary_file = self.sink_file or self.source_file
        if not self.primary_function:
            self.primary_function = self.sink_function or self.source_function
        if self.primary_anchor and not self.primary_line:
            self.primary_line = int(self.primary_anchor.get("end_line") or 0)
        if not self.primary_line:
            self.primary_line = self.sink_line or self.source_line or 0


@dataclass(frozen=True, slots=True)
class ReachabilityAnalysis:
    findings: tuple[VulnerabilityFinding, ...]
    target_file: str | None = None
    target_path: str | None = None
    codegraph_failures: tuple[str, ...] = ()
    review_failures: tuple[FrontierReviewFailure, ...] = ()
