# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os

from .base import AnalyzerEvidence, AnalyzerRequest
from .c_family_ast import CFamilyAstMixin
from .c_family_flow import CFamilyFlowMixin
from .c_family_macro import CFamilyMacroMixin
from .c_family_xref import CFamilyXrefMixin
from .treesitter_runtime import TreeSitterRuntime


class CFamilyTriageAnalyzer(
    CFamilyAstMixin, CFamilyFlowMixin, CFamilyMacroMixin, CFamilyXrefMixin
):
    def __init__(
        self,
        *,
        codebase_path: str,
        language_name: str,
        supported_extensions: list[str] | None = None,
    ):
        self.codebase_path = codebase_path
        self.language_name = language_name
        self.runtime = TreeSitterRuntime(language_name)
        if supported_extensions:
            self.supported_extensions = {
                str(ext).lower() for ext in supported_extensions
            }
        else:
            self.supported_extensions = set()

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
                unresolved_hops=[
                    f"TREE_SITTER_UNAVAILABLE:{self.language_name}:{self.runtime.init_error or 'unknown_error'}"
                ],
            )

        try:
            parsed = self.runtime.parse_file(request.codebase_path, request.file_path)
        except Exception as exc:
            return AnalyzerEvidence(
                supported=False,
                language=self.language_name,
                summary="Tree-sitter parse failed; falling back to text tools.",
                unresolved_hops=[
                    f"TREE_SITTER_PARSE_FAILURE:{request.file_path}:{exc}"
                ],
            )

        source = bytes(parsed.text, "utf-8")
        root = parsed.tree.root_node
        node_index, parent_map = self._index_tree(root)

        definitions = self._collect_definitions(root, source)
        references = self._collect_references(root, source)
        calls = self._collect_calls(root, source)
        functions = self._collect_functions(root, source)

        wanted = self._select_wanted_symbols(
            definitions=definitions,
            references=references,
            calls=calls,
            request=request,
        )

        flow_hops, flow_unresolved, flow_fallback_targets, path_sections = (
            self._build_structured_flow_chain(
                request=request,
                root=root,
                source=source,
                node_index=node_index,
                parent_map=parent_map,
                functions=functions,
                max_hops=12,
                max_depth=3,
            )
        )

        citations: list[str] = []
        resolution_chain: list[str] = []
        unresolved_hops: list[str] = list(flow_unresolved)
        fallback_targets: list[str] = list(flow_fallback_targets)
        sections: list[str] = list(path_sections)
        flow_chain: list[str] = []

        for hop in flow_hops:
            citations.append(f"{request.file_path}:{hop.line}")
            flow_chain.append(
                f"{hop.role} at {request.file_path}:{hop.line} - {hop.detail}"
            )
            resolution_chain.append(
                f"{hop.role} hop resolved at {request.file_path}:{hop.line} ({hop.detail})"
            )

        for symbol in wanted:
            sym_defs = definitions.get(symbol, [])
            sym_calls = calls.get(symbol, [])
            sym_refs = references.get(symbol, [])

            if sym_defs:
                d = sym_defs[0]
                citations.append(f"{request.file_path}:{d.line}")
                resolution_chain.append(
                    f"{symbol} definition resolved at {request.file_path}:{d.line}"
                )
            else:
                # Macro symbols are resolved through explicit macro-chain analysis.
                if not symbol.isupper():
                    unresolved_hops.append(f"SYMBOL_DEFINITION_UNRESOLVED:{symbol}")
                    if self._is_actionable_symbol(symbol):
                        fallback_targets.append(symbol)

            if sym_calls:
                c = sym_calls[0]
                citations.append(f"{request.file_path}:{c.line}")
                resolution_chain.append(
                    f"{symbol} call/reference observed at {request.file_path}:{c.line}"
                )
            elif sym_refs and sym_defs:
                r = sym_refs[0]
                citations.append(f"{request.file_path}:{r.line}")
                resolution_chain.append(
                    f"{symbol} identifier usage observed at {request.file_path}:{r.line}"
                )

            if sym_defs or sym_calls or sym_refs:
                parts = []
                if sym_defs:
                    parts.append(
                        "defs=" + ", ".join(str(item.line) for item in sym_defs[:3])
                    )
                if sym_calls:
                    parts.append(
                        "calls=" + ", ".join(str(item.line) for item in sym_calls[:3])
                    )
                if sym_refs:
                    parts.append(
                        "refs=" + ", ".join(str(item.line) for item in sym_refs[:3])
                    )
                sections.append(f"evidence.local.{symbol}: " + " | ".join(parts))

        include_context_files = self._collect_include_context_files(
            codebase_path=request.codebase_path,
            file_path=request.file_path,
            source_text=parsed.text,
            depth=2,
        )
        macro_sections, macro_citations, macro_resolution, macro_unresolved = (
            self._analyze_macro_semantics(
                symbols=wanted,
                include_files=include_context_files,
                codebase_path=request.codebase_path,
            )
        )
        sections.extend(macro_sections)
        citations.extend(macro_citations)
        resolution_chain.extend(macro_resolution)
        unresolved_hops.extend(macro_unresolved)

        unresolved_hops, xref_sections, xref_citations, xref_resolution = (
            self._resolve_unresolved_hops_across_codebase(
                unresolved_hops=unresolved_hops,
                codebase_path=request.codebase_path,
                file_path=request.file_path,
                top_symbol_hint=wanted[:6],
            )
        )
        sections.extend(xref_sections)
        citations.extend(xref_citations)
        resolution_chain.extend(xref_resolution)

        dedup_citations: list[str] = []
        seen = set()
        for citation in citations:
            if citation in seen:
                continue
            seen.add(citation)
            dedup_citations.append(citation)
            if len(dedup_citations) >= max(1, request.max_citations):
                break

        unresolved_hops = self._dedup_keep_order(unresolved_hops)[
            : request.max_citations
        ]
        ast_seed_targets = [
            symbol for symbol in wanted if self._is_actionable_symbol(symbol)
        ]
        fallback_targets = self._compute_fallback_targets_from_unresolved(
            unresolved_hops=unresolved_hops,
            preferred_symbols=ast_seed_targets + fallback_targets,
            limit=request.max_citations,
        )

        if flow_chain:
            sections.insert(0, "evidence.flow_chain: " + " | ".join(flow_chain[:10]))

        summary = (
            f"Tree-sitter({self.language_name}) analyzed {request.file_path}; "
            f"matched {len([s for s in wanted if s in definitions or s in calls])} symbol(s); "
            f"flow_hops={len(flow_hops)}."
        )

        return AnalyzerEvidence(
            supported=True,
            language=self.language_name,
            summary=summary,
            citations=dedup_citations,
            resolution_chain=resolution_chain[: request.max_citations],
            flow_chain=flow_chain[: request.max_citations],
            unresolved_hops=unresolved_hops,
            fallback_targets=fallback_targets,
            sections=sections[:16],
        )


def build_c_family_analyzer_factory(
    language_name: str,
    *,
    supported_extensions: list[str] | None = None,
):

    def _factory(codebase_path: str):
        return CFamilyTriageAnalyzer(
            codebase_path=codebase_path,
            language_name=language_name,
            supported_extensions=supported_extensions,
        )

    return _factory
