# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import bisect
import os
import re
import threading
from collections import OrderedDict, defaultdict
from typing import Any

from .anchor import (
    CONFIDENCE_DISAMBIGUATED,
    CONFIDENCE_EXACT,
    CONFIDENCE_FUZZY,
    KIND_RANGE,
    CodeAnchor,
    content_hash,
    normalize_path,
)

_TS_LANGUAGE_BY_EXT = {
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
}

_TRIVIAL_LINE_MIN_LEN = 8

_C_FUNC_DEF = re.compile(
    r"(?:^|\n)[^\n;{}#/]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:\n\s*)?\{",
    re.MULTILINE,
)


def _norm_line(line: str) -> str:
    return " ".join(line.split())


class SourceMap:
    """
    Cached, line-indexed view of a single source file.

    Provides the canonical numbered rendering, byte↔line conversion and
    deterministic snippet → :class:`CodeAnchor` resolution used by every
    pipeline that needs to attribute a finding to a location.
    """

    def __init__(self, rel_path: str, text: str):
        self.rel_path = normalize_path(rel_path)
        self.text = text
        self.lines: list[str] = text.splitlines()
        self.line_offsets: list[int] = self._compute_line_offsets(text)
        self._tree: Any | None = None
        self._tree_attempted = False
        # (start_line, end_line, name) for each top-level function
        self._functions: list[tuple[int, int, str]] | None = None

    @classmethod
    def for_file(cls, codebase_path: str, rel_path: str) -> "SourceMap | None":
        return SourceRepository.default().get(codebase_path, rel_path)

    @classmethod
    def for_text(cls, rel_path: str, text: str) -> "SourceMap":
        return cls(rel_path, text)

    @staticmethod
    def _compute_line_offsets(text: str) -> list[int]:
        offsets = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                offsets.append(i + 1)
        return offsets

    @property
    def line_count(self) -> int:
        return len(self.lines)

    def byte_to_line(self, byte_offset: int) -> int:
        if byte_offset <= 0:
            return 1
        idx = bisect.bisect_right(self.line_offsets, byte_offset) - 1
        return max(1, idx + 1)

    def line_to_byte(self, line: int) -> int:
        line = max(1, min(line, len(self.line_offsets)))
        return self.line_offsets[line - 1]

    def line_end_byte(self, line: int) -> int:
        if line < len(self.line_offsets):
            return self.line_offsets[line] - 1
        return len(self.text)

    def numbered_slice(
        self, start_line: int, end_line: int, *, max_lines: int | None = None
    ) -> str:
        if not self.lines:
            return ""
        start = max(1, min(start_line, self.line_count))
        end = max(start, min(end_line, self.line_count))
        if max_lines is not None and (end - start + 1) > max_lines:
            end = start + max_lines - 1
        width = len(str(end))
        return "\n".join(
            f"{i:>{width}}: {self.lines[i - 1]}" for i in range(start, end + 1)
        )

    def context_slice(
        self, line: int, *, radius: int = 2, max_chars: int | None = None
    ) -> str:
        line = max(1, line)
        out = self.numbered_slice(line - radius, line + radius)
        return out[:max_chars] if max_chars else out

    def function_slice(
        self,
        start_line: int,
        end_line: int = 0,
        *,
        max_chars: int = 6000,
        fallback_lines: int = 80,
    ) -> str:
        if not end_line:
            span = self.find_function_span(near_line=start_line)
            end_line = (
                span[1] if span else min(self.line_count, start_line + fallback_lines)
            )
        max_lines = max(1, max_chars // 80)
        return self.numbered_slice(start_line, end_line, max_lines=max_lines)

    def find_function_span(
        self, *, name: str | None = None, near_line: int = 1
    ) -> tuple[int, int] | None:
        spans = self._function_spans()
        if name is not None:
            spans = [(s, e, n) for s, e, n in spans if n == name]
        if not spans:
            return None
        s, e, _ = min(
            spans,
            key=lambda t: (
                0 if t[0] <= near_line <= t[1] else 1,
                abs(t[0] - near_line),
            ),
        )
        return s, e

    @staticmethod
    def number_text(text: str, start_line: int) -> str:
        lines = text.splitlines()
        if not lines:
            return ""
        end = start_line + len(lines) - 1
        width = len(str(end))
        return "\n".join(
            f"{start_line + i:>{width}}: {ln}" for i, ln in enumerate(lines)
        )

    def anchor_for_lines(
        self,
        start_line: int,
        end_line: int,
        *,
        symbol: str | None = None,
        kind: str = KIND_RANGE,
        confidence: str = CONFIDENCE_EXACT,
    ) -> CodeAnchor:
        start = max(1, min(start_line, self.line_count or 1))
        end = max(start, min(end_line, self.line_count or start))
        sb = self.line_to_byte(start)
        eb = self.line_end_byte(end)
        if symbol is None:
            symbol = self.enclosing_symbol(start)
        return CodeAnchor(
            file_path=self.rel_path,
            start_line=start,
            end_line=end,
            start_col=0,
            end_col=len(self.lines[end - 1]) if self.lines else 0,
            start_byte=sb,
            end_byte=eb,
            symbol=symbol,
            kind=kind,
            content_hash=content_hash(self.text[sb:eb]),
            confidence=confidence,
        )

    def anchor_for_bytes(
        self,
        start_byte: int,
        end_byte: int,
        *,
        symbol: str | None = None,
        kind: str = KIND_RANGE,
        confidence: str = CONFIDENCE_EXACT,
    ) -> CodeAnchor:
        sl = self.byte_to_line(start_byte)
        el = self.byte_to_line(max(start_byte, end_byte - 1))
        if symbol is None:
            symbol = self.enclosing_symbol(sl)
        return CodeAnchor(
            file_path=self.rel_path,
            start_line=sl,
            end_line=el,
            start_col=start_byte - self.line_to_byte(sl),
            end_col=max(0, end_byte - self.line_to_byte(el)),
            start_byte=start_byte,
            end_byte=end_byte,
            symbol=symbol,
            kind=kind,
            content_hash=content_hash(self.text[start_byte:end_byte]),
            confidence=confidence,
        )

    def anchor_for_ts_node(
        self, node: Any, *, symbol: str | None = None, kind: str = KIND_RANGE
    ) -> CodeAnchor:
        return self.anchor_for_bytes(
            int(node.start_byte()),
            int(node.end_byte()),
            symbol=symbol,
            kind=kind,
        )

    def verify_lines(
        self, start_line: int, end_line: int, snippet: str
    ) -> CodeAnchor | None:
        """Return an exact anchor when ``snippet`` matches lines start..end."""
        if not (1 <= start_line <= end_line <= self.line_count):
            return None
        actual = [_norm_line(ln) for ln in self.lines[start_line - 1 : end_line]]
        wanted = [_norm_line(ln) for ln in snippet.splitlines() if _norm_line(ln)]
        if not wanted:
            return None
        joined_actual = " ".join(a for a in actual if a)
        joined_wanted = " ".join(wanted)
        if joined_wanted in joined_actual or joined_actual in joined_wanted:
            return self.anchor_for_lines(
                start_line, end_line, confidence=CONFIDENCE_EXACT
            )
        return None

    def resolve_issue(
        self,
        *,
        snippet: str,
        start_line: int | None = None,
        end_line: int | None = None,
        hint: range | None = None,
        context_text: str = "",
    ) -> CodeAnchor:
        """
        Resolve a model-reported issue location.

        Trusts ``start_line``/``end_line`` only when ``snippet`` actually
        appears there; otherwise locates ``snippet`` deterministically,
        biased by ``hint`` and ``context_text``. Always returns an anchor
        (``confidence == "unresolved"`` when nothing matches).
        """
        if isinstance(start_line, int) and isinstance(end_line, int):
            verified = self.verify_lines(start_line, end_line, snippet or "")
            if verified is not None:
                return verified
        if snippet:
            located = self.resolve_snippet(
                snippet, hint=hint, context_text=context_text
            )
            if located is not None:
                return located
        return CodeAnchor.unresolved(self.rel_path)

    def resolve_snippet(
        self,
        snippet: str,
        *,
        hint: range | None = None,
        context_text: str = "",
    ) -> CodeAnchor | None:
        if not snippet or not self.lines:
            return None

        snippet_lines = [ln.rstrip() for ln in snippet.splitlines()]
        while snippet_lines and not snippet_lines[0].strip():
            snippet_lines.pop(0)
        while snippet_lines and not snippet_lines[-1].strip():
            snippet_lines.pop()
        if not snippet_lines:
            return None

        anchor = self._resolve_verbatim(snippet_lines, hint, context_text)
        if anchor is not None:
            return anchor
        return self._resolve_fuzzy(snippet_lines, hint)

    def _resolve_verbatim(
        self, snippet_lines: list[str], hint: range | None, context_text: str
    ) -> CodeAnchor | None:
        needle = "\n".join(snippet_lines)
        haystack = "\n".join(ln.rstrip() for ln in self.lines)

        starts: list[int] = []
        pos = haystack.find(needle)
        while pos != -1:
            starts.append(pos)
            pos = haystack.find(needle, pos + 1)
        if not starts:
            return None

        spans = [
            (
                haystack.count("\n", 0, s) + 1,
                haystack.count("\n", 0, s) + len(snippet_lines),
            )
            for s in starts
        ]

        if len(spans) == 1:
            sl, el = spans[0]
            return self.anchor_for_lines(sl, el, confidence=CONFIDENCE_EXACT)

        chosen = self._disambiguate(spans, hint, context_text)
        return self.anchor_for_lines(
            chosen[0], chosen[1], confidence=CONFIDENCE_DISAMBIGUATED
        )

    def _disambiguate(
        self,
        spans: list[tuple[int, int]],
        hint: range | None,
        context_text: str,
    ) -> tuple[int, int]:
        if hint is not None:
            in_hint = [s for s in spans if s[0] in hint or s[1] in hint]
            if len(in_hint) == 1:
                return in_hint[0]
            if in_hint:
                spans = in_hint
        if context_text:
            for span in spans:
                sym = self.enclosing_symbol(span[0])
                if sym:
                    short = sym.split("::")[-1]
                    if short and short in context_text:
                        return span
        return spans[0]

    def _resolve_fuzzy(
        self, snippet_lines: list[str], hint: range | None
    ) -> CodeAnchor | None:
        wanted: list[str] = []
        for ln in snippet_lines:
            n = _norm_line(ln)
            if len(n) >= _TRIVIAL_LINE_MIN_LEN and n not in {"{", "}", "};"}:
                wanted.append(n)
        if not wanted:
            return None

        index: dict[str, list[int]] = defaultdict(list)
        for i, ln in enumerate(self.lines, start=1):
            index[_norm_line(ln)].append(i)

        hits: list[int] = []
        for w in wanted:
            hits.extend(index.get(w, ()))
        if not hits:
            return None
        hits.sort()

        window = max(len(snippet_lines), 3)
        best_start, best_count = hits[0], 1
        j = 0
        for i, h in enumerate(hits):
            while hits[j] < h - window:
                j += 1
            count = i - j + 1
            in_hint = hint is not None and h in hint
            best_in_hint = hint is not None and best_start in hint
            if count > best_count or (
                count == best_count and in_hint and not best_in_hint
            ):
                best_start, best_count = hits[j], count

        cluster = [h for h in hits if best_start <= h <= best_start + window]
        sl, el = min(cluster), max(cluster)
        return self.anchor_for_lines(sl, el, confidence=CONFIDENCE_FUZZY)

    def enclosing_symbol(self, line: int) -> str | None:
        for start, end, name in self._function_spans():
            if start <= line <= end:
                return f"{self.rel_path}::{name}"
        return None

    def _function_spans(self) -> list[tuple[int, int, str]]:
        if self._functions is not None:
            return self._functions
        self._functions = self._spans_from_tree() or self._spans_from_regex()
        self._functions.sort()
        return self._functions

    def _spans_from_tree(self) -> list[tuple[int, int, str]]:
        tree = self._ensure_tree()
        if tree is None:
            return []
        try:
            from metis.engine.reachability.c_family_nodes import (
                _identifier_from_node,
                _node_child_by_field_name,
                _node_children,
                _node_end_line,
                _node_kind,
                _node_line,
            )
        except Exception:
            return []

        source = self.text.encode("utf-8")
        out: list[tuple[int, int, str]] = []
        stack = [tree.root_node()]
        while stack:
            node = stack.pop()
            if _node_kind(node) in {"function_definition", "method_definition"}:
                decl = _node_child_by_field_name(node, "declarator")
                name = _identifier_from_node(decl or node, source)
                if name:
                    out.append((_node_line(node), _node_end_line(node), name))
            for child in reversed(_node_children(node)):
                stack.append(child)
        return out

    def _spans_from_regex(self) -> list[tuple[int, int, str]]:
        ext = os.path.splitext(self.rel_path)[1].lower()
        if ext not in _TS_LANGUAGE_BY_EXT:
            return []
        out: list[tuple[int, int, str]] = []
        for m in _C_FUNC_DEF.finditer(self.text):
            name = m.group(1)
            if name in {"if", "for", "while", "switch", "return", "sizeof"}:
                continue
            brace_pos = m.end() - 1
            depth = 1
            i = brace_pos + 1
            n = len(self.text)
            while i < n and depth > 0:
                ch = self.text[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                i += 1
            start_line = self.byte_to_line(m.start(1))
            end_line = self.byte_to_line(i - 1)
            out.append((start_line, end_line, name))
        return out

    def _ensure_tree(self) -> Any | None:
        if self._tree is not None or self._tree_attempted:
            return self._tree
        self._tree_attempted = True
        ext = os.path.splitext(self.rel_path)[1].lower()
        lang = _TS_LANGUAGE_BY_EXT.get(ext)
        if not lang:
            return None
        try:
            from tree_sitter_language_pack import get_parser

            self._tree = get_parser(lang).parse(self.text)
        except Exception:
            self._tree = None
        return self._tree


class SourceRepository:
    """Process-wide LRU cache of :class:`SourceMap` keyed by (path, mtime, size)."""

    _instance: "SourceRepository | None" = None
    _instance_lock = threading.Lock()

    def __init__(self, capacity: int = 256):
        self._capacity = capacity
        self._cache: "OrderedDict[tuple[str, float, int], SourceMap]" = OrderedDict()
        self._lock = threading.Lock()

    @classmethod
    def default(cls) -> "SourceRepository":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def get(self, codebase_path: str, rel_path: str) -> SourceMap | None:
        if os.path.isabs(rel_path):
            full = rel_path
            try:
                rel = os.path.relpath(rel_path, codebase_path)
            except ValueError:
                rel = rel_path
        else:
            full = os.path.join(codebase_path, rel_path)
            rel = rel_path
        try:
            st = os.stat(full)
        except OSError:
            return None
        key = (os.path.abspath(full), st.st_mtime, st.st_size)
        with self._lock:
            smap = self._cache.get(key)
            if smap is not None:
                self._cache.move_to_end(key)
                return smap
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            return None
        smap = SourceMap(rel, text)
        with self._lock:
            self._cache[key] = smap
            self._cache.move_to_end(key)
            while len(self._cache) > self._capacity:
                self._cache.popitem(last=False)
        return smap

    def clear(self):
        with self._lock:
            self._cache.clear()
