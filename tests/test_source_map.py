# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import textwrap

import pytest

from metis.engine.source import CodeAnchor, SourceMap, SourceRepository
from metis.engine.source.anchor import (
    CONFIDENCE_DISAMBIGUATED,
    CONFIDENCE_EXACT,
    CONFIDENCE_FUZZY,
    CONFIDENCE_UNRESOLVED,
    content_hash,
)


C_FIXTURE = textwrap.dedent(
    """\
    #include <string.h>

    int safe(const char *s) {
        return strlen(s);
    }

    int parse(char *buf, int len) {
        char tmp[8];
        if (len > 0) {
            memcpy(tmp, buf, len);
        }
        return tmp[0];
    }

    int other(char *buf, int len) {
        char tmp[8];
        if (len > 0) {
            memcpy(tmp, buf, len);
        }
        return tmp[0];
    }
    """
)


@pytest.fixture
def smap():
    return SourceMap.for_text("src/foo.c", C_FIXTURE)


def test_anchor_round_trip_and_ids():
    a = CodeAnchor(
        file_path=".\\src\\foo.c",
        start_line=7,
        end_line=12,
        symbol="src/foo.c::parse",
        content_hash="abc123",
    )
    assert a.file_path == "src/foo.c"
    assert a.display_id() == "src/foo.c#src/foo.c::parse@7-12"
    assert a.stable_id() == "src/foo.c#src/foo.c::parse~abc123"
    assert CodeAnchor.from_dict(a.to_dict()) == a
    assert CodeAnchor.from_dict(None) is None


def test_anchor_unresolved():
    a = CodeAnchor.unresolved("foo.c")
    assert a.confidence == CONFIDENCE_UNRESOLVED
    assert a.start_line == 0 and a.end_line == 0


def test_numbered_slice_one_indexed_and_clamped(smap):
    out = smap.numbered_slice(1, 3)
    lines = out.splitlines()
    assert lines[0].lstrip().startswith("1: #include")
    assert lines[2].lstrip().startswith("3: int safe")
    # clamps past EOF
    assert smap.numbered_slice(100, 200) == smap.numbered_slice(
        smap.line_count, smap.line_count
    )


def test_numbered_slice_max_lines(smap):
    out = smap.numbered_slice(1, 100, max_lines=2)
    assert len(out.splitlines()) == 2


def test_number_text_static():
    out = SourceMap.number_text("a\nb\nc", start_line=10)
    assert out.splitlines() == ["10: a", "11: b", "12: c"]


def test_byte_line_round_trip(smap):
    for line in (1, 3, 7, 10, smap.line_count):
        b = smap.line_to_byte(line)
        assert smap.byte_to_line(b) == line
        assert smap.byte_to_line(smap.line_end_byte(line)) == line


def test_anchor_for_lines_carries_hash_and_bytes(smap):
    a = smap.anchor_for_lines(7, 13)
    assert a.start_line == 7 and a.end_line == 13
    assert a.start_byte == smap.line_to_byte(7)
    assert a.content_hash
    assert smap.text[a.start_byte : a.end_byte].startswith("int parse")


def test_resolve_exact_unique(smap):
    a = smap.resolve_snippet("int parse(char *buf, int len) {")
    assert a is not None
    assert a.start_line == 7 and a.end_line == 7
    assert a.confidence == CONFIDENCE_EXACT


def test_resolve_disambiguated_by_hint(smap):
    snippet = "        memcpy(tmp, buf, len);"
    a = smap.resolve_snippet(snippet, hint=range(15, 22))
    assert a is not None
    assert a.start_line == 18
    assert a.confidence == CONFIDENCE_DISAMBIGUATED


def test_resolve_disambiguated_by_context_symbol(smap):
    snippet = "        memcpy(tmp, buf, len);"
    a = smap.resolve_snippet(
        snippet, context_text="overflow in other() when len exceeds 8"
    )
    assert a is not None
    assert a.start_line == 18
    assert a.confidence == CONFIDENCE_DISAMBIGUATED


def test_resolve_disambiguated_no_hint_picks_first(smap):
    a = smap.resolve_snippet("        memcpy(tmp, buf, len);")
    assert a is not None
    assert a.start_line == 10
    assert a.confidence == CONFIDENCE_DISAMBIGUATED


def test_resolve_fuzzy_when_reformatted(smap):
    # LLM rewrapped / re-indented but tokens preserved per line
    snippet = "char tmp[8];\n  memcpy(tmp, buf, len);"
    a = smap.resolve_snippet(snippet, hint=range(7, 14))
    assert a is not None
    assert a.confidence == CONFIDENCE_FUZZY
    assert 8 <= a.start_line <= 10 and 8 <= a.end_line <= 12


def test_resolve_miss_returns_none(smap):
    assert smap.resolve_snippet("this code does not appear anywhere") is None
    assert smap.resolve_snippet("   \n  \n") is None


def test_verify_lines_match(smap):
    a = smap.verify_lines(10, 10, "memcpy(tmp, buf, len);")
    assert a is not None and a.confidence == CONFIDENCE_EXACT


def test_verify_lines_mismatch(smap):
    assert smap.verify_lines(3, 3, "memcpy(tmp, buf, len);") is None
    assert smap.verify_lines(0, 0, "x") is None
    assert smap.verify_lines(1, 9999, "x") is None


def test_enclosing_symbol(smap):
    assert smap.enclosing_symbol(10) == "src/foo.c::parse"
    assert smap.enclosing_symbol(18) == "src/foo.c::other"
    assert smap.enclosing_symbol(1) is None


def test_anchor_for_lines_auto_symbol(smap):
    a = smap.anchor_for_lines(10, 10)
    assert a.symbol == "src/foo.c::parse"


def test_stable_id_invariant_under_line_shift():
    base = SourceMap.for_text("src/foo.c", C_FIXTURE)
    shifted = SourceMap.for_text("src/foo.c", "\n\n\n" + C_FIXTURE)

    a1 = base.resolve_snippet("memcpy(tmp, buf, len);", hint=range(7, 14))
    a2 = shifted.resolve_snippet("memcpy(tmp, buf, len);", hint=range(10, 17))
    assert a1 is not None and a2 is not None
    assert a1.start_line != a2.start_line
    assert a1.stable_id() == a2.stable_id()


def test_content_hash_detects_drift():
    assert content_hash("memcpy(a,b,c)") != content_hash("memmove(a,b,c)")
    assert content_hash("  memcpy(a,b,c)  ") == content_hash("memcpy(a,b,c)")


def test_repository_caches_by_mtime(tmp_path):
    p = tmp_path / "f.c"
    p.write_text("int x;\n")
    repo = SourceRepository(capacity=4)
    m1 = repo.get(str(tmp_path), "f.c")
    m2 = repo.get(str(tmp_path), "f.c")
    assert m1 is m2
    assert repo.get(str(tmp_path), "missing.c") is None


def test_repository_lru_eviction(tmp_path):
    repo = SourceRepository(capacity=2)
    for name in ("a.c", "b.c", "c.c"):
        (tmp_path / name).write_text("int x;\n")
        repo.get(str(tmp_path), name)
    assert len(repo._cache) == 2


def test_split_snippet_returns_offsets():
    from metis.utils import split_snippet

    text = "a\nb\nc\nd\n"
    chunks = split_snippet(text, max_tokens=1)
    assert chunks[0][1] == 1
    assert all(isinstance(c, tuple) and len(c) == 2 for c in chunks)
    assert "".join(c for c, _ in chunks) == text
    starts = [s for _, s in chunks]
    assert starts == sorted(starts)


def test_enrich_issues_uses_model_lines_when_verified(tmp_path):
    from metis.utils import enrich_issues

    p = tmp_path / "foo.c"
    p.write_text(C_FIXTURE)
    issues = [
        {
            "issue": "overflow",
            "code_snippet": "memcpy(tmp, buf, len);",
            "start_line": 10,
            "end_line": 10,
        }
    ]
    enrich_issues(str(p), issues)
    assert issues[0]["line_number"] == 10
    assert issues[0]["anchor"]["confidence"] == CONFIDENCE_EXACT
    assert issues[0]["anchor"]["symbol"] == "foo.c::parse"


def test_enrich_issues_falls_back_when_model_lines_wrong(tmp_path):
    from metis.utils import enrich_issues

    p = tmp_path / "foo.c"
    p.write_text(C_FIXTURE)
    issues = [
        {
            "issue": "overflow in other()",
            "reasoning": "the call to memcpy in other lacks a bound",
            "code_snippet": "memcpy(tmp, buf, len);",
            "start_line": 3,  # wrong
            "end_line": 3,
        }
    ]
    enrich_issues(str(p), issues, hint=range(15, 22))
    assert issues[0]["line_number"] == 18
    assert issues[0]["anchor"]["confidence"] == CONFIDENCE_DISAMBIGUATED


def test_enrich_issues_unresolved_when_no_match(tmp_path):
    from metis.utils import enrich_issues

    p = tmp_path / "foo.c"
    p.write_text(C_FIXTURE)
    issues = [{"issue": "x", "code_snippet": "not in this file at all"}]
    enrich_issues(str(p), issues)
    assert issues[0]["line_number"] == 0
    assert issues[0]["anchor"]["confidence"] == CONFIDENCE_UNRESOLVED


def test_annotate_chunk_anchors():
    from metis.engine.helpers import annotate_chunk_anchors

    class _Doc:
        id_ = "src/foo.c"
        text = C_FIXTURE

    class _Node:
        def __init__(self, t):
            self.text = t
            self.metadata = {}

    chunks = [
        _Node("int parse(char *buf, int len) {\n    char tmp[8];"),
        _Node("        memcpy(tmp, buf, len);"),
    ]
    annotate_chunk_anchors(_Doc(), chunks)
    assert chunks[0].metadata["start_line"] == 7
    assert chunks[0].metadata["symbol"] == "src/foo.c::parse"
    assert chunks[0].metadata["anchor_id"].startswith("src/foo.c#src/foo.c::parse~")
    # second chunk hits both parse and other; first occurrence wins
    assert chunks[1].metadata["start_line"] in (10, 18)


def test_for_file_uses_default_repo(tmp_path):
    SourceRepository.default().clear()
    (tmp_path / "g.c").write_text(C_FIXTURE)
    smap = SourceMap.for_file(str(tmp_path), "g.c")
    assert smap is not None
    assert smap.resolve_snippet("int parse(char *buf, int len) {").start_line == 7
