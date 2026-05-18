# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class AnalyzerRequest:
    codebase_path: str
    file_path: str
    line: int
    finding_message: str
    finding_snippet: str
    finding_rule_id: str
    candidate_symbols: list[str] = field(default_factory=list)
    max_citations: int = 12


@dataclass(frozen=True)
class AnalyzerEvidence:
    supported: bool
    language: str = ""
    summary: str = ""
    citations: list[str] = field(default_factory=list)
    resolution_chain: list[str] = field(default_factory=list)
    flow_chain: list[str] = field(default_factory=list)
    unresolved_hops: list[str] = field(default_factory=list)
    fallback_targets: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)


class TriageAnalyzer(Protocol):
    def supports_file(self, rel_path: str) -> bool:
        """Return True when this analyzer can process the file path."""

    def collect_evidence(self, request: AnalyzerRequest) -> AnalyzerEvidence:
        """Collect deterministic static evidence for triage."""
