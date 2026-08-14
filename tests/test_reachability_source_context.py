# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import re

from metis.engine.codegraph import CallSite, FunctionNode
from metis.engine.nodes.reachability.source_context import (
    _build_file_grouped_node_chunks,
)


def _character_count(text: str) -> int:
    return len(text)


def _node(name: str, start: int, end: int) -> FunctionNode:
    return FunctionNode(
        unique_name=f"sample.c::{name}",
        file_path="sample.c",
        name=name,
        line_number=start,
        end_line=end,
    )


def _rendered_lines(chunks: list[tuple[list[FunctionNode], str]]) -> set[int]:
    return {
        int(match.group(1))
        for _nodes, text in chunks
        for line in text.splitlines()
        if (match := re.match(r"\s*(\d+):", line))
    }


def test_function_chunks_cover_every_source_line_and_callsite(tmp_path):
    lines = ["void target(void) {"]
    lines.extend(f"  operation_{index}();" for index in range(1, 18))
    lines.append("}")
    (tmp_path / "sample.c").write_text("\n".join(lines))
    target = _node("target", 1, len(lines))
    target.call_sites = [
        CallSite("operation_2", 3, 0),
        CallSite("operation_17", 18, 0),
    ]

    chunks = _build_file_grouped_node_chunks(
        str(tmp_path),
        [target],
        max_tokens=150,
        token_counter=_character_count,
    )

    assert _rendered_lines(chunks) == set(range(1, len(lines) + 1))
    assert all(target in nodes for nodes, _text in chunks)
    assert all(_character_count(text) <= 150 for _nodes, text in chunks)
    assert {call.line for call in target.call_sites} <= _rendered_lines(chunks)


def test_function_chunks_never_cross_files_and_follow_source_order(tmp_path):
    (tmp_path / "a.c").write_text(
        "void first(void) {}\nvoid second(void) {}\n",
        encoding="utf-8",
    )
    (tmp_path / "b.c").write_text("void third(void) {}\n", encoding="utf-8")
    first = FunctionNode("a.c::first", "a.c", "first", 1, end_line=1)
    second = FunctionNode("a.c::second", "a.c", "second", 2, end_line=2)
    third = FunctionNode("b.c::third", "b.c", "third", 1, end_line=1)

    chunks = _build_file_grouped_node_chunks(
        str(tmp_path),
        [third, second, first],
        max_tokens=10_000,
        token_counter=_character_count,
    )

    assert [[node.unique_name for node in nodes] for nodes, _text in chunks] == [
        ["a.c::first", "a.c::second"],
        ["b.c::third"],
    ]
    assert all(len({node.file_path for node in nodes}) == 1 for nodes, _text in chunks)
    assert all("Function a.c::" not in text for _nodes, text in chunks)
    assert all("===== FILE:" not in text for _nodes, text in chunks)
