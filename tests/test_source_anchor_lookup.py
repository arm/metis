# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Preserve finding locations while bounding minified-code anchor lookup."""

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from metis.engine.source import SourceMap
from metis.engine.source import source_map
from metis.engine.source.anchor import CONFIDENCE_DISAMBIGUATED
from metis.engine.source.anchor import CONFIDENCE_EXACT


@pytest.mark.parametrize(
    "text,snippet,hint,expected,confidence",
    [
        ("a;b;b;", "b", None, (1, 1), CONFIDENCE_DISAMBIGUATED),
        ("é;\r\nx;  \r\nx;\r\n", "x;", range(3, 4), (3, 3), CONFIDENCE_DISAMBIGUATED),
        ("é;\r\nx;  \r\nend;\r\n", "x;\nend;", None, (2, 3), CONFIDENCE_EXACT),
        ("x;\nx;\n", "x;", range(9, 10), (1, 1), CONFIDENCE_DISAMBIGUATED),
        ("aaa\naaa\n", "aa", range(2, 3), (2, 2), CONFIDENCE_DISAMBIGUATED),
        ("start;\n  unique();  \n", "\n  unique();\n", None, (2, 2), CONFIDENCE_EXACT),
    ],
)
def test_anchor_lookup_preserves_lines_bytes_and_confidence(
    text,
    snippet,
    hint,
    expected,
    confidence,
) -> None:
    source = SourceMap.for_text("fixture.js", text)
    anchor = source.resolve_snippet(snippet, hint=hint)
    assert anchor is not None
    assert (anchor.start_line, anchor.end_line) == expected
    assert anchor == source.anchor_for_lines(*expected, confidence=confidence)


@pytest.mark.parametrize("hint", [None, range(1, 8), range(1, 4)])
def test_repeated_anchor_keeps_symbol_context_and_hint_precedence(hint) -> None:
    source = SourceMap.for_text(
        "fixture.c",
        "void first() {\n  call();\n}\nvoid second() {\n  call();\n}\n",
    )
    anchor = source.resolve_snippet("call();", hint=hint, context_text="second")
    assert anchor is not None
    assert anchor.start_line == (2 if hint == range(1, 4) else 5)
    assert anchor.confidence == CONFIDENCE_DISAMBIGUATED


def test_missing_verbatim_match_still_uses_fuzzy_resolution() -> None:
    source = SourceMap.for_text("fixture.js", "const answer = 42;\n")
    assert source.resolve_snippet("const   answer = 42;") is not None
    assert source.resolve_snippet("absent();") is None


def test_chunks_sharing_a_line_hash_original_source_once(monkeypatch) -> None:
    hashed = []
    original_hash = source_map.content_hash

    def capture_hash(text):
        hashed.append(text)
        return original_hash(text)

    monkeypatch.setattr(source_map, "content_hash", capture_hash)
    source = SourceMap.for_bytes(
        "fixture.js",
        b"const x = 1;",
        anchor_source=b"const y = 2;",
    )
    anchors = [source.resolve_snippet(snippet) for snippet in ("x", "1", "const")]
    assert hashed == ["const y = 2;"]
    assert all(
        anchor.content_hash == original_hash("const y = 2;") for anchor in anchors
    )


def test_source_hash_cache_has_bounded_retention() -> None:
    lines = [f"line {number}" for number in range(1, 301)]
    source = SourceMap.for_text("fixture.txt", "\n".join(lines))
    with ThreadPoolExecutor(max_workers=8) as pool:
        anchors = list(pool.map(source.anchor_for_lines, range(1, 301), range(1, 301)))
    assert [anchor.start_line for anchor in anchors] == list(range(1, 301))
    assert [anchor.content_hash for anchor in anchors] == [
        source_map.content_hash(line) for line in lines
    ]
    assert len(source._anchor_hashes) == 256


def test_minified_repeated_anchor_finishes_within_a_bounded_process() -> None:
    # A short snippet repeated across a 2 MB line made the former algorithm
    # repeatedly scan source prefixes for every match. The subprocess bound
    # prevents a regression from stranding the test worker.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
from metis.engine.source import SourceMap
from metis.engine.source.anchor import CONFIDENCE_DISAMBIGUATED
source = SourceMap.for_text('bundle.js', 'x;' * 1_000_000)
for hint in (None, range(1, 2)):
    anchor = source.resolve_snippet('x', hint=hint)
    assert anchor.start_line == anchor.end_line == 1
    assert anchor.confidence == CONFIDENCE_DISAMBIGUATED
""",
        ],
        timeout=20,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
