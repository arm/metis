# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import re

from .base import AnalyzerEvidence, AnalyzerRequest
from .treesitter_runtime import TreeSitterRuntime


class GenericTreeSitterAnalyzer:
    def __init__(
        self,
        *,
        codebase_path: str,
        language_name: str,
        supported_extensions: list[str],
    ):
        self.codebase_path = codebase_path
        self.language_name = language_name
        self.runtime = TreeSitterRuntime(language_name)
        self.supported_extensions = {str(ext).lower() for ext in supported_extensions}

    def supports_file(self, rel_path: str) -> bool:
        ext = os.path.splitext(rel_path or "")[1].lower()
        return ext in self.supported_extensions

    def collect_evidence(self, request: AnalyzerRequest) -> AnalyzerEvidence:
        if not self.supports_file(request.file_path):
            return AnalyzerEvidence(
                supported=False,
                language=self.language_name,
                summary="Analyzer does not support this file extension.",
            )

        if not self.runtime.is_available:
            return AnalyzerEvidence(
                supported=False,
                language=self.language_name,
                summary="Tree-sitter runtime unavailable; falling back to text tools.",
                unresolved_hops=[f"TREE_SITTER_UNAVAILABLE:{self.language_name}"],
            )

        try:
            parsed = self.runtime.parse_file(request.codebase_path, request.file_path)
        except Exception as exc:
            return AnalyzerEvidence(
                supported=False,
                language=self.language_name,
                summary="Tree-sitter parse failed; falling back to text tools.",
                unresolved_hops=[f"TREE_SITTER_PARSE_FAILURE:{exc}"],
            )

        lines = parsed.text.splitlines()
        anchor = max(1, int(request.line or 1))
        lo = max(1, anchor - 12)
        hi = min(max(anchor + 12, lo), max(1, len(lines)))
        window = "\n".join(lines[lo - 1 : hi])

        call_names = self._extract_call_names(window)[:6]
        citations = [f"{request.file_path}:{anchor}"]
        flow_chain = [f"source at {request.file_path}:{anchor} - reported context"]
        resolution = [
            f"source hop resolved at {request.file_path}:{anchor} (reported context)"
        ]
        unresolved: list[str] = []

        if "if " in window or "if(" in window or "guard" in window.lower():
            flow_chain.append(
                f"check at {request.file_path}:{anchor} - local conditional context"
            )
            resolution.append(
                f"check hop resolved at {request.file_path}:{anchor} (local conditional context)"
            )

        if call_names:
            sink = call_names[0]
            role = "unknown"
            flow_chain.append(f"{role} at {request.file_path}:{anchor} - call '{sink}'")
            resolution.append(
                f"{role} hop resolved at {request.file_path}:{anchor} (call '{sink}')"
            )
            unresolved.append(f"FLOW_SINK_CLASS_UNRESOLVED:{sink}")
        else:
            unresolved.append("FLOW_SINK_NOT_FOUND")

        sections = []
        if call_names:
            sections.append("calls: " + ", ".join(call_names[:6]))
        sections.append("flow: " + " | ".join(flow_chain))

        return AnalyzerEvidence(
            supported=True,
            language=self.language_name,
            summary=f"Tree-sitter({self.language_name}) analyzed {request.file_path}; generic structural pass.",
            citations=citations,
            resolution_chain=resolution[: request.max_citations],
            flow_chain=flow_chain[: request.max_citations],
            unresolved_hops=unresolved[: request.max_citations],
            fallback_targets=call_names[:3],
            sections=sections[:12],
        )

    def _extract_call_names(self, text: str) -> list[str]:
        raw = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text or "")
        out: list[str] = []
        seen = set()
        for name in raw:
            if name in seen:
                continue
            seen.add(name)
            out.append(name)
            if len(out) >= 10:
                break
        return out


def build_generic_treesitter_analyzer_factory(
    language_name: str,
    *,
    supported_extensions: list[str],
):

    def _factory(codebase_path: str):
        return GenericTreeSitterAnalyzer(
            codebase_path=codebase_path,
            language_name=language_name,
            supported_extensions=supported_extensions,
        )

    return _factory
