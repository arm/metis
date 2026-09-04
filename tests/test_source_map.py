# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import gc
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor

import pytest

from metis.engine.source import CodeAnchor
from metis.engine.source import SourceMap
from metis.engine.source import SourceRepository
from metis.engine.source.anchor import CONFIDENCE_DISAMBIGUATED
from metis.engine.source.anchor import CONFIDENCE_EXACT
from metis.engine.source.anchor import CONFIDENCE_FUZZY
from metis.engine.source.anchor import CONFIDENCE_UNRESOLVED
from metis.engine.source.anchor import content_hash

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
    assert SourceMap.number_text("a\finside\r\nb\vinside\n", 1) == (
        "1: a\finside\n2: b\vinside"
    )


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
    blank = SourceMap.for_text("source.c", "             \n")
    assert blank.verify_lines(1, 1, "inactive_bug();") is None


def test_enclosing_symbol(smap):
    assert smap.enclosing_symbol(10) == "src/foo.c::parse"
    assert smap.enclosing_symbol(18) == "src/foo.c::other"
    assert smap.enclosing_symbol(1) is None


def test_context_slice(smap):
    out = smap.context_slice(10, radius=1)
    assert out.splitlines()[0].lstrip().startswith("9:")
    assert out.splitlines()[-1].lstrip().startswith("11:")
    assert len(smap.context_slice(10, radius=2, max_chars=20)) == 20


def test_function_slice_uses_explicit_end(smap):
    out = smap.function_slice(7, 13)
    lines = out.splitlines()
    assert lines[0].lstrip().startswith("7:")
    assert lines[-1].lstrip().startswith("13:")


def test_function_slice_infers_end(smap):
    out = smap.function_slice(7)
    assert out.splitlines()[-1].lstrip().startswith("13:")


def test_function_slice_uses_rendered_character_budget():
    text = "\n".join(
        ["int many_short_lines(void) {"]
        + [f"  value += {index};" for index in range(100)]
        + ["  return value;", "}"]
    )
    source_map = SourceMap.for_text("src/short-lines.c", text)
    complete = source_map.numbered_slice(1, source_map.line_count)

    assert len(complete) < 4096
    assert (
        source_map.function_slice(1, source_map.line_count, max_chars=4096) == complete
    )


def test_function_slice_does_not_exceed_rendered_character_budget():
    text = "\n".join(
        ["int long_function(void) {"]
        + [f"  value += {index};" for index in range(100)]
        + ["  return value;", "}"]
    )
    source_map = SourceMap.for_text("src/long.c", text)

    rendered = source_map.function_slice(1, source_map.line_count, max_chars=160)

    assert len(rendered) <= 160
    assert rendered.startswith("  1: int long_function")


def test_find_function_span(smap):
    assert smap.find_function_span(name="parse") == (7, 13)
    assert smap.find_function_span(name="other", near_line=18) == (15, 21)
    assert smap.find_function_span(name="missing") is None
    assert smap.find_function_span(near_line=10) == (7, 13)


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


def test_source_map_preserves_crlf_byte_offsets() -> None:
    source_map = SourceMap.for_bytes("crlf.c", b"a\r\nb\r\n")

    assert source_map.line_to_byte(2) == 3
    anchor = source_map.anchor_for_lines(1, 1)
    assert (anchor.end_byte, anchor.end_col) == (1, 1)
    assert source_map.byte_slice(anchor.start_byte, anchor.end_byte) == "a"


@pytest.mark.parametrize(
    "source",
    [b"", b"\n", b"\r", b"a\r\nb\n", "αé\n尾".encode(), bytes(range(256))],
)
def test_source_map_offsets_match_byte_newlines(source: bytes) -> None:
    source_map = SourceMap.for_bytes("source.txt", source)

    assert source_map.line_count == source.count(b"\n") + bool(
        source and not source.endswith(b"\n")
    )
    assert source_map.line_offsets == [
        0,
        *(index + 1 for index, byte in enumerate(source) if byte == 10),
    ]


@pytest.mark.parametrize("fallback", (False, True))
def test_symbol_disambiguation_keeps_invalid_utf8_byte_positions(monkeypatch, fallback):
    raw = b"/* " + b"\xff" * 64 + b" */\n"
    raw += b"void first(void) { operation(); }\nvoid second(void) { operation(); }\n"
    source_map = SourceMap.for_bytes("source.c", raw)
    if fallback:
        monkeypatch.setattr(source_map, "_spans_from_tree", lambda: [])
    anchor = source_map.resolve_issue(snippet="operation();", context_text="second")
    assert (anchor.start_line, anchor.end_line) == (3, 3)
    assert anchor.start_byte == raw.index(b"void second")
    assert anchor.symbol == "source.c::second"


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


def test_source_map_extracts_tree_sitter_utf8_byte_spans():
    source = "// café\nvoid target(void) { dangerous(); }\n"
    smap = SourceMap.for_text("src/utf8.c", source)
    encoded = source.encode("utf-8")
    start = encoded.index(b"dangerous")
    end = start + len(b"dangerous()")

    assert smap.byte_slice(start, end) == "dangerous()"
    assert smap.byte_to_line(start) == 2


def test_resolve_issue_uses_model_lines_when_verified(smap):
    a = smap.resolve_issue(snippet="memcpy(tmp, buf, len);", start_line=10, end_line=10)
    assert a.end_line == 10
    assert a.confidence == CONFIDENCE_EXACT


def test_resolve_issue_strips_numbered_prompt_prefixes(smap):
    a = smap.resolve_issue(
        snippet="9:         if (len > 0) {\n10:             memcpy(tmp, buf, len);",
        start_line=9,
        end_line=10,
    )

    assert (a.start_line, a.end_line, a.confidence) == (9, 10, CONFIDENCE_EXACT)
    assert a.symbol == "src/foo.c::parse"


def test_resolve_issue_preserves_assembly_numeric_label():
    source_map = SourceMap.for_text("src/start.s", "1: nop\nb 1b\n")

    anchor = source_map.resolve_issue(snippet="1: nop", start_line=1, end_line=1)

    assert (anchor.start_line, anchor.end_line, anchor.confidence) == (
        1,
        1,
        CONFIDENCE_EXACT,
    )


def test_resolve_issue_falls_back_when_model_lines_wrong(smap):
    a = smap.resolve_issue(
        snippet="memcpy(tmp, buf, len);",
        start_line=3,
        end_line=3,
        hint=range(15, 22),
        context_text="overflow in other() — memcpy in other lacks a bound",
    )
    assert a.end_line == 18
    assert a.confidence == CONFIDENCE_DISAMBIGUATED


def test_resolve_issue_unresolved_when_no_match(smap):
    a = smap.resolve_issue(snippet="not in this file at all")
    assert a.end_line == 0
    assert a.confidence == CONFIDENCE_UNRESOLVED


def test_review_node_parse_attaches_anchor():
    from metis.engine.nodes.simple_llm_review.graph import review_node_parse

    smap = SourceMap.for_text("src/foo.c", C_FIXTURE)
    state = {
        "source_map": smap,
        "chunk_start": 7,
        "chunk_end": 13,
        "parsed_reviews": [
            {
                "issue": "overflow",
                "code_snippet": "memcpy(tmp, buf, len);",
                "start_line": 10,
                "end_line": 10,
            }
        ],
    }
    out = review_node_parse(state)
    issue = out["parsed_reviews"][0]
    assert issue["line_number"] == 10
    assert issue["anchor"]["confidence"] == CONFIDENCE_EXACT
    assert issue["anchor"]["symbol"] == "src/foo.c::parse"


def test_review_node_parse_no_source_map():
    from metis.engine.nodes.simple_llm_review.graph import review_node_parse

    state = {"parsed_reviews": [{"issue": "x", "code_snippet": "y"}]}
    out = review_node_parse(state)
    assert out["parsed_reviews"][0]["anchor"] is None
    assert out["parsed_reviews"][0]["line_number"] == 0


def test_review_node_parse_line_number_is_start():
    from metis.engine.nodes.simple_llm_review.graph import review_node_parse

    smap = SourceMap.for_text("src/foo.c", C_FIXTURE)
    state = {
        "source_map": smap,
        "mode": "file",
        "chunk_start": 7,
        "chunk_end": 13,
        "parsed_reviews": [
            {
                "issue": "overflow",
                "code_snippet": "    char tmp[8];\n    if (len > 0) {\n        memcpy(tmp, buf, len);",
            }
        ],
    }
    out = review_node_parse(state)
    issue = out["parsed_reviews"][0]
    assert issue["anchor"]["start_line"] == 8
    assert issue["anchor"]["end_line"] == 10
    assert issue["line_number"] == 8


def test_review_node_parse_patch_mode_resolves_against_original():
    from metis.engine.nodes.simple_llm_review.graph import review_node_parse

    smap = SourceMap.for_text("src/foo.c", C_FIXTURE)
    state = {
        "source_map": smap,
        "mode": "patch",
        "chunk_start": 1,
        "chunk_end": 3,
        "parsed_reviews": [
            {
                "issue": "overflow in parse",
                "reasoning": "memcpy in parse() lacks bound",
                "code_snippet": "memcpy(tmp, buf, len);",
            }
        ],
    }
    out = review_node_parse(state)
    issue = out["parsed_reviews"][0]
    # chunk hint (1-3) is ignored in patch mode; symbol-name disambiguation
    # via context_text picks parse() at line 10
    assert issue["line_number"] == 10
    assert issue["anchor"]["symbol"] == "src/foo.c::parse"


def test_normalize_review_fields():
    from metis.engine.nodes.simple_llm_review.prompt import normalize_review_fields

    assert normalize_review_fields({"severity": "med"})["severity"] == "Medium"
    assert normalize_review_fields({"severity": "CRITICAL"})["severity"] == "Critical"
    assert normalize_review_fields({})["cwe"] == "CWE-Unknown"
    assert normalize_review_fields({"cwe": "CWE-79"})["cwe"] == "CWE-79"


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


def test_source_map_does_not_cache_native_tree_across_threads(tmp_path):
    SourceRepository.default().clear()
    (tmp_path / "threaded.c").write_text(
        "void threaded(void) {}\n",
        encoding="utf-8",
    )
    unraisable: list[str] = []
    previous_hook = sys.unraisablehook
    sys.unraisablehook = lambda error: unraisable.append(str(error.exc_value))
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            symbol = executor.submit(
                lambda: SourceMap.for_file(
                    str(tmp_path),
                    "threaded.c",
                ).enclosing_symbol(1)
            ).result()
        SourceRepository.default().clear()
        gc.collect()
    finally:
        sys.unraisablehook = previous_hook

    assert symbol == "threaded.c::threaded"
    assert not any("unsendable" in error for error in unraisable)
