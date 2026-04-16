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


_C_FAMILY_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".hxx", ".cxx"}


def is_c_family_file_path(file_path: str) -> bool:
    ext = Path(file_path or "").suffix.lower()
    return ext in _C_FAMILY_EXTENSIONS


def is_c_macro_like_symbol(text: str) -> bool:
    value = str(text or "").strip()
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{1,127}$", value):
        return False
    return value.upper() == value


def collect_c_macro_like_calls_from_scope(
    node,
    source: bytes,
    *,
    max_macros: int,
    collect_identifier_symbols,
) -> list[str]:
    macros: list[str] = []
    seen: set[str] = set()

    def _walk(cur) -> None:
        if len(macros) >= max_macros:
            return
        node_type = str(getattr(cur, "type", "") or "")
        if node_type == "call_expression":
            fn_node = None
            try:
                fn_node = cur.child_by_field_name("function")
            except Exception:
                fn_node = None
            if fn_node is not None:
                fn_name = collect_identifier_symbols(fn_node, source, max_symbols=1)
                if fn_name:
                    candidate = str(fn_name[0]).strip()
                    if is_c_macro_like_symbol(candidate) and candidate not in seen:
                        seen.add(candidate)
                        macros.append(candidate)
        for child in getattr(cur, "children", []) or []:
            _walk(child)

    _walk(node)
    return macros


def collect_c_macro_definition_sections(
    *,
    sections: list[str],
    file_path: str,
    macro_names: list[str],
    max_sections: int,
    max_citations: int,
    related_grep_max_lines: int,
    related_grep_max_chars: int,
    max_targeted_hits: int,
    max_targeted_context_hits: int,
    targeted_hit_radius: int,
    targeted_hit_context_max_lines: int,
    targeted_hit_context_max_chars: int,
    safe_tool_capture,
    parse_grep_hits,
    find_name_paths=None,
    root_probe_path: str | None = ".",
) -> tuple[list[str], dict[str, str]]:
    if not macro_names:
        return [], {}
    if len(sections) >= max_sections:
        return list(macro_names), {}

    include_paths = _extract_include_candidates(
        sections=sections,
        file_path=file_path,
        max_sections=max_sections,
        related_grep_max_lines=related_grep_max_lines,
        related_grep_max_chars=related_grep_max_chars,
        safe_tool_capture=safe_tool_capture,
        find_name_paths=find_name_paths,
    )
    base_paths = _build_fallback_paths(file_path)
    candidate_paths: list[str] = []
    path_candidates = [file_path] + include_paths + base_paths
    if root_probe_path:
        path_candidates.append(root_probe_path)
    for path in path_candidates:
        p = str(path or "").strip()
        if not p or p in candidate_paths:
            continue
        candidate_paths.append(p)
        if len(candidate_paths) >= 10:
            break

    unresolved: list[str] = []
    resolved_semantics: dict[str, str] = {}
    for macro in macro_names[:max_citations]:
        if len(sections) >= max_sections:
            unresolved.append(macro)
            continue
        resolved = False
        define_pattern = (
            rf"^[[:space:]]*#[[:space:]]*define[[:space:]]+"
            rf"{re.escape(macro)}([^A-Za-z0-9_]|$)"
        )
        for path in candidate_paths:
            if len(sections) >= max_sections:
                break
            output = safe_tool_capture(
                tool_name="grep",
                tool_args={
                    "pattern": define_pattern,
                    "path": path,
                    "mode": "macro_define",
                },
                section_label=f"MACRO_DEFINE_GREP {macro} IN {path}",
                max_lines=related_grep_max_lines,
                max_chars=related_grep_max_chars,
                append_error_section=False,
                invoke=lambda p=path, q=define_pattern: ("grep", p, q),
            )
            if output is None:
                continue
            hits = parse_grep_hits(output, max_hits=max_targeted_hits)
            if not hits:
                continue
            resolved = True
            resolved_kind = _classify_macro_define_semantics(
                macro=macro, grep_output=output
            )
            if resolved_kind:
                resolved_semantics[macro] = resolved_kind
                if len(sections) < max_sections:
                    sections.append(f"[MACRO_RESOLUTION]\n{macro} -> {resolved_kind}")
            for hit_path, hit_line in hits[:max_targeted_context_hits]:
                if len(sections) >= max_sections:
                    break
                start = max(1, hit_line - targeted_hit_radius)
                end = hit_line + targeted_hit_radius
                safe_tool_capture(
                    tool_name="sed",
                    tool_args={
                        "path": hit_path,
                        "start_line": start,
                        "end_line": end,
                        "mode": "macro_define",
                    },
                    section_label=f"MACRO_DEFINE_CONTEXT {macro} {hit_path}:{start}-{end}",
                    max_lines=targeted_hit_context_max_lines,
                    max_chars=targeted_hit_context_max_chars,
                    append_error_section=False,
                    invoke=lambda p=hit_path, s=start, e=end: ("sed", p, s, e),
                )
            break
        if not resolved:
            unresolved.append(macro)
    return unresolved, resolved_semantics


def _classify_macro_define_semantics(*, macro: str, grep_output: str) -> str:
    for raw in str(grep_output or "").splitlines():
        parts = raw.split(":", 2)
        if len(parts) < 3:
            continue
        define_text = str(parts[2] or "").strip()
        if not define_text:
            continue
        if not re.search(rf"^\s*#\s*define\s+{re.escape(macro)}\b", define_text):
            continue
        lowered = define_text.lower()
        if re.search(r"\b(__builtin_)?alloca\s*\(", lowered) or re.search(
            r"\b(__builtin_)?alloca\b", lowered
        ):
            return "alloca"
        return "defined"
    return ""


def _extract_include_candidates(
    *,
    sections: list[str],
    file_path: str,
    max_sections: int,
    related_grep_max_lines: int,
    related_grep_max_chars: int,
    safe_tool_capture,
    find_name_paths=None,
) -> list[str]:
    if not file_path or len(sections) >= max_sections:
        return []
    include_pattern = r'^[[:space:]]*#[[:space:]]*include[[:space:]]+[<"][^>"]+[>"]'
    output = safe_tool_capture(
        tool_name="grep",
        tool_args={
            "pattern": include_pattern,
            "path": file_path,
            "mode": "include_scan",
        },
        section_label=f"INCLUDE_SCAN {file_path}",
        max_lines=related_grep_max_lines,
        max_chars=related_grep_max_chars,
        append_error_section=False,
        invoke=lambda: ("grep", file_path, include_pattern),
    )
    if output is None:
        return []
    include_paths: list[str] = []
    seen: set[str] = set()
    base_dir = str(Path(file_path).parent)
    for raw in str(output or "").splitlines():
        parts = raw.split(":", 2)
        if len(parts) < 3:
            continue
        text = parts[2]
        m = re.search(r'#\s*include\s+[<"]([^>"]+)[>"]', text)
        if not m:
            continue
        name = str(m.group(1) or "").strip()
        if not name:
            continue
        candidates = [name]
        resolved = _resolve_include_name_with_index(name, find_name_paths)
        if resolved:
            candidates.extend(resolved)
        if "/" not in name and base_dir and base_dir != ".":
            candidates.append(f"{base_dir}/{name}")
        for cand in candidates:
            norm = str(Path(cand)).replace("\\", "/")
            if not norm or norm in seen:
                continue
            seen.add(norm)
            include_paths.append(norm)
            if len(include_paths) >= 8:
                return include_paths
    return include_paths


def _resolve_include_name_with_index(name: str, resolver) -> list[str]:
    if not callable(resolver):
        return []
    base = Path(name).name
    if not base:
        return []
    try:
        found = resolver(base)
    except Exception:
        return []
    out: list[str] = []
    for item in found or []:
        path = str(item or "").replace("\\", "/").strip()
        if not path:
            continue
        if path.endswith(f"/{base}") or path == base:
            out.append(path)
            if len(out) >= 8:
                break
    return out


def _build_fallback_paths(file_path: str, global_scope: str = ".") -> list[str]:
    fallback_paths: list[str] = []
    if file_path:
        file_dir = str(Path(file_path).parent)
        if file_dir and file_dir != ".":
            fallback_paths.append(file_dir)
        top = file_path.split("/", 1)[0]
        if top and top not in fallback_paths:
            fallback_paths.append(top)
    if not fallback_paths:
        fallback_paths = [global_scope]
    return sorted(set(fallback_paths), key=lambda p: p.lower())
