# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from pathlib import Path
import re

from .c_family_analyzer_common import _CrossFileHit


class CFamilyXrefMixin:
    def _resolve_unresolved_hops_across_codebase(
        self,
        *,
        unresolved_hops: list[str],
        codebase_path: str,
        file_path: str,
        top_symbol_hint: list[str],
    ) -> tuple[list[str], list[str], list[str], list[str]]:
        remaining: list[str] = []
        sections: list[str] = []
        citations: list[str] = []
        resolution: list[str] = []

        for hop in unresolved_hops:
            symbol = self._extract_symbol_from_unresolved(hop)
            if not symbol or not self._is_actionable_symbol(symbol):
                remaining.append(hop)
                continue
            hits = self._search_symbol_hits(
                codebase_path=codebase_path,
                file_path=file_path,
                symbol=symbol,
                prefer_hint=top_symbol_hint,
                max_hits=2,
            )
            if not hits:
                remaining.append(hop)
                continue
            hit = self._choose_best_symbol_hit(hits)
            citations.append(f"{hit.file_path}:{hit.line}")
            sections.append(
                f"evidence.cross_file.{symbol}: {hit.kind} at {hit.file_path}:{hit.line}"
            )
            resolution.append(
                f"cross-file symbol resolution for {symbol} found {hit.kind} at {hit.file_path}:{hit.line}"
            )
        return remaining, sections, citations, resolution

    def _choose_best_symbol_hit(self, hits: list[_CrossFileHit]) -> _CrossFileHit:
        if not hits:
            return _CrossFileHit(symbol="", file_path="", line=0, kind="none")
        has_decl = next((h for h in hits if h.kind == "declaration"), None)
        has_asm = next((h for h in hits if h.kind == "asm_label"), None)
        if has_decl and has_asm:
            return _CrossFileHit(
                symbol=has_decl.symbol,
                file_path=has_asm.file_path,
                line=has_asm.line,
                kind=f"asm_impl(decl:{has_decl.file_path}:{has_decl.line})",
            )
        priority = {
            "asm_label": 0,
            "function_like": 1,
            "macro": 2,
            "declaration": 3,
            "function_ref": 4,
        }
        ordered = sorted(
            hits,
            key=lambda h: (priority.get(h.kind, 9), h.file_path.lower(), h.line),
        )
        return ordered[0]

    def _extract_symbol_from_unresolved(self, hop: str) -> str:
        text = str(hop or "").strip()
        if ":" not in text:
            return ""
        parts = text.split(":")
        if len(parts) < 2:
            return ""
        candidate = parts[1].strip()
        if not candidate:
            return ""
        candidate = candidate.split(":")[0].strip()
        return candidate

    def _search_symbol_hits(
        self,
        *,
        codebase_path: str,
        file_path: str,
        symbol: str,
        prefer_hint: list[str],
        max_hits: int,
    ) -> list[_CrossFileHit]:
        hits: list[_CrossFileHit] = []
        fn_re = re.compile(rf"\b{re.escape(symbol)}\s*\(")
        define_re = re.compile(rf"^\s*#\s*define\s+{re.escape(symbol)}\b")
        decl_re = re.compile(rf"\b{re.escape(symbol)}\b")
        asm_label_re = re.compile(
            rf"(KAI_ASM_FUNCTION_LABEL\s*\(\s*{re.escape(symbol)}\s*\)|\b{re.escape(symbol)}\s*:)"
        )
        for rel in self._walk_code_files(
            codebase_path=codebase_path,
            file_path=file_path,
            prefer_hint=prefer_hint,
            limit=1400,
        ):
            try:
                text = (Path(codebase_path).resolve() / rel).read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
            except Exception:
                continue
            ext = os.path.splitext(rel)[1].lower()
            for idx, raw in enumerate(text.splitlines(), start=1):
                line = raw.strip()
                if not line:
                    continue
                if define_re.search(line):
                    hits.append(
                        _CrossFileHit(
                            symbol=symbol, file_path=rel, line=idx, kind="macro"
                        )
                    )
                    if len(hits) >= max_hits * 3:
                        break
                    continue
                if asm_label_re.search(line) and ext in {".s"}:
                    hits.append(
                        _CrossFileHit(
                            symbol=symbol, file_path=rel, line=idx, kind="asm_label"
                        )
                    )
                    if len(hits) >= max_hits * 3:
                        break
                    continue
                if fn_re.search(line):
                    kind = "function_ref"
                    if "{" in line or line.endswith(")") or line.endswith("){"):
                        kind = "function_like"
                    hits.append(
                        _CrossFileHit(symbol=symbol, file_path=rel, line=idx, kind=kind)
                    )
                    if len(hits) >= max_hits * 3:
                        break
                    continue
                if decl_re.search(line) and ";" in line and "(" in line and ")" in line:
                    hits.append(
                        _CrossFileHit(
                            symbol=symbol,
                            file_path=rel,
                            line=idx,
                            kind="declaration",
                        )
                    )
                    if len(hits) >= max_hits * 3:
                        break
            if len(hits) >= max_hits * 3:
                break
        return hits[: max_hits * 3]

    def _walk_code_files(
        self,
        *,
        codebase_path: str,
        file_path: str,
        prefer_hint: list[str],
        limit: int,
    ) -> list[str]:
        root = Path(codebase_path).resolve()
        allowed_ext = {
            ".c",
            ".h",
            ".cc",
            ".cpp",
            ".hpp",
            ".hh",
            ".hxx",
            ".cxx",
            ".S",
            ".s",
        }
        base_top = file_path.split("/", 1)[0] if "/" in file_path else ""
        prefer_set = {base_top} if base_top else set()
        for hint in prefer_hint:
            if hint and "/" in hint:
                prefer_set.add(hint.split("/", 1)[0])

        preferred: list[str] = []
        rest: list[str] = []
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                ext = os.path.splitext(name)[1]
                if ext not in allowed_ext:
                    continue
                full = Path(dirpath) / name
                try:
                    rel = full.relative_to(root).as_posix()
                except Exception:
                    continue
                bucket = rest
                top = rel.split("/", 1)[0] if "/" in rel else rel
                if top in prefer_set:
                    bucket = preferred
                bucket.append(rel)
                if len(preferred) + len(rest) >= limit:
                    break
            if len(preferred) + len(rest) >= limit:
                break
        return preferred + rest

    def _is_critical_unresolved_hop(self, hop: str) -> bool:
        text = str(hop or "").strip()
        if not text:
            return False
        critical_prefixes = (
            "FLOW_ANCHOR_NOT_FOUND",
            "FLOW_ENCLOSING_FUNCTION_UNRESOLVED",
            "FLOW_SINK_NOT_FOUND",
            "FLOW_EXTERNAL_CALLEE_UNRESOLVED:",
            "TREE_SITTER_UNAVAILABLE:",
            "TREE_SITTER_PARSE_FAILURE:",
            "MACRO_SEMANTICS_UNRESOLVED:",
        )
        for prefix in critical_prefixes:
            if text.startswith(prefix):
                return True
        return False

    def _compute_fallback_targets_from_unresolved(
        self,
        *,
        unresolved_hops: list[str],
        preferred_symbols: list[str],
        limit: int,
    ) -> list[str]:
        out: list[str] = []
        for hop in unresolved_hops:
            if not self._is_critical_unresolved_hop(hop):
                continue
            symbol = self._extract_symbol_from_unresolved(hop)
            if symbol and self._is_actionable_symbol(symbol):
                out.append(symbol)
        for symbol in preferred_symbols:
            if symbol and self._is_actionable_symbol(symbol):
                out.append(symbol)
        out = self._dedup_keep_order(out)
        return out[:limit]
