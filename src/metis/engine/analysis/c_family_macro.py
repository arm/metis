# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
import re

from .c_family_analyzer_common import _CrossFileHit
from .c_family_helpers import parse_includes_from_text, resolve_include_path


class CFamilyMacroMixin:
    def _collect_include_context_files(
        self,
        *,
        codebase_path: str,
        file_path: str,
        source_text: str,
        depth: int,
    ) -> list[str]:
        root = Path(codebase_path).resolve()
        start = (root / file_path).resolve()
        files: list[str] = []
        visited: set[Path] = set()

        def to_rel(path: Path) -> str:
            try:
                return path.relative_to(root).as_posix()
            except Exception:
                return path.as_posix()

        def walk(current_path: Path, text: str, level: int):
            if level > depth:
                return
            if current_path in visited:
                return
            visited.add(current_path)
            if current_path.is_file():
                files.append(to_rel(current_path))
            if level == depth:
                return
            for include in parse_includes_from_text(text):
                resolved = resolve_include_path(
                    include=include,
                    current_path=current_path,
                    root=root,
                )
                if resolved is None or not resolved.is_file():
                    continue
                try:
                    next_text = resolved.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                walk(resolved, next_text, level + 1)

        walk(start, source_text or "", 0)
        return self._dedup_keep_order(files)[:48]

    def _analyze_macro_semantics(
        self,
        *,
        symbols: list[str],
        include_files: list[str],
        codebase_path: str,
    ) -> tuple[list[str], list[str], list[str], list[str]]:
        sections: list[str] = []
        citations: list[str] = []
        resolution: list[str] = []
        unresolved: list[str] = []
        if not symbols:
            return sections, citations, resolution, unresolved

        files_to_scan = list(include_files)
        macro_candidates = [s for s in symbols if s.isupper() and len(s) >= 3]
        for macro in macro_candidates[:8]:
            chain = self._resolve_macro_chain(
                macro=macro,
                files=files_to_scan,
                codebase_path=codebase_path,
                max_depth=6,
            )
            if not chain:
                unresolved.append(f"MACRO_SEMANTICS_UNRESOLVED:{macro}")
                continue
            kind = self._classify_macro_semantics(macro=macro, defs=chain)
            best = chain[0]
            citations.append(f"{best.file_path}:{best.line}")
            sections.append(
                f"evidence.macro_chain.{macro}: kind={kind} defined_at={best.file_path}:{best.line} chain={' -> '.join(item.symbol for item in chain[:6])}"
            )
            resolution.append(
                f"macro semantics for {macro} resolved as {kind} at {best.file_path}:{best.line}"
            )
            if kind in {"unknown", "assume_only"}:
                unresolved.append(f"MACRO_SEMANTICS_WEAK:{macro}:{kind}")
        return sections, citations, resolution, unresolved

    def _resolve_macro_chain(
        self,
        *,
        macro: str,
        files: list[str],
        codebase_path: str,
        max_depth: int,
    ) -> list[_CrossFileHit]:
        chain: list[_CrossFileHit] = []
        seen: set[str] = set()
        current = macro
        for _ in range(max_depth):
            if not current or current in seen:
                break
            seen.add(current)
            defs = self._scan_macro_definitions(
                macro=current,
                files=files,
                codebase_path=codebase_path,
            )
            if not defs:
                break
            top = defs[0]
            chain.append(top)
            next_macro = self._extract_macro_alias(top.kind, top.symbol)
            if not next_macro:
                break
            current = next_macro
        return chain

    def _scan_macro_definitions(
        self,
        *,
        macro: str,
        files: list[str],
        codebase_path: str,
    ) -> list[_CrossFileHit]:
        out: list[_CrossFileHit] = []
        pattern = re.compile(rf"^\s*#\s*define\s+{re.escape(macro)}\b")
        for rel in files[:64]:
            try:
                path = Path(codebase_path).resolve() / rel
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for idx, raw in enumerate(text.splitlines(), start=1):
                if pattern.search(raw):
                    out.append(
                        _CrossFileHit(
                            symbol=macro,
                            file_path=rel,
                            line=idx,
                            kind=raw.strip(),
                        )
                    )
                    break
        return out

    def _extract_macro_alias(self, define_line: str, symbol: str) -> str:
        line = str(define_line or "").strip()
        if not line:
            return ""
        m = re.match(
            r"^\s*#\s*define\s+[A-Za-z_][A-Za-z0-9_]*\s+([A-Za-z_][A-Za-z0-9_]*)\b",
            line,
        )
        if not m:
            return ""
        target = str(m.group(1) or "").strip()
        if not target or target == symbol:
            return ""
        if target.startswith("__"):
            return ""
        return target

    def _classify_macro_semantics(
        self,
        *,
        macro: str,
        defs: list[_CrossFileHit],
    ) -> str:
        expanded = " ".join(item.kind for item in defs).lower()
        if "__builtin_assume" in expanded or "__assume(" in expanded:
            return "assume_only"
        if "assert" in expanded or "abort" in expanded or "trap" in expanded:
            return "assert_like"
        if "do" in expanded and "while" in expanded:
            return "macro_block"
        return "unknown"
