# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections import defaultdict
from collections.abc import Callable
from collections.abc import Sequence

from metis.engine.codegraph import FunctionNode
from metis.engine.source import SourceMap
from metis.utils import source_lines
from metis.utils import split_snippet


def _source_map(
    codebase_path: str,
    file_path: str,
    source_for_path: Callable[[str], bytes | None] | None,
) -> SourceMap | None:
    source = source_for_path(file_path) if source_for_path is not None else None
    if source is None:
        return SourceMap.for_file(codebase_path, file_path)
    return SourceMap.for_bytes(file_path, source)


def _build_file_grouped_node_chunks(
    codebase_path: str,
    nodes: Sequence[FunctionNode],
    *,
    max_tokens: int,
    token_counter: Callable[[str], int],
    source_for_path: Callable[[str], bytes | None] | None = None,
) -> list[tuple[list[FunctionNode], str]]:
    by_file: dict[str, list[FunctionNode]] = defaultdict(list)
    for function in sorted(
        nodes,
        key=lambda node: (
            str(node.file_path),
            int(node.line_number or 0),
            str(node.name),
        ),
    ):
        by_file[function.file_path].append(function)

    chunks: list[tuple[list[FunctionNode], str]] = []
    current_nodes: list[FunctionNode] = []
    current_node_names: set[str] = set()
    current_parts: list[str] = []

    def flush_current() -> None:
        nonlocal current_nodes, current_node_names, current_parts
        if current_parts:
            chunks.append((list(current_nodes), "\n\n".join(current_parts)))
            current_nodes = []
            current_node_names = set()
            current_parts = []

    for file_path in sorted(by_file):
        flush_current()
        source_map = _source_map(codebase_path, file_path, source_for_path)
        if source_map is None:
            continue
        for function in by_file[file_path]:
            body = source_map.numbered_slice(
                function.line_number,
                function.end_line or function.line_number,
            )
            if not body:
                continue
            if any(
                token_counter(line) > max_tokens
                for line in source_lines(body, keepends=True)
            ):
                raise ValueError("max_tokens cannot hold one numbered source line")
            for body_part, _start_line in split_snippet(
                body,
                max_tokens,
                token_counter,
            ):
                combined = "\n\n".join((*current_parts, body_part))
                if current_parts and token_counter(combined) > max_tokens:
                    flush_current()
                if function.unique_name not in current_node_names:
                    current_nodes.append(function)
                    current_node_names.add(function.unique_name)
                current_parts.append(body_part)

    flush_current()
    return chunks
