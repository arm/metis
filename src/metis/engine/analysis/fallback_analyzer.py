# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from .base import AnalyzerEvidence, AnalyzerRequest


class FallbackTriageAnalyzer:
    def supports_file(self, rel_path: str) -> bool:
        return bool(rel_path)

    def collect_evidence(self, request: AnalyzerRequest) -> AnalyzerEvidence:
        return AnalyzerEvidence(
            supported=False,
            summary="Analyzer unavailable; using deterministic text-tool fallback.",
            unresolved_hops=[
                f"No Tree-sitter analyzer available for {request.file_path or '<unknown>'}"
            ],
        )
