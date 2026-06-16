# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from collections import defaultdict

from metis.engine.source import SourceMap

from .limits import (
    FUNCTION_BODY_DEFAULT_CHARS,
    FUNCTION_BODY_FALLBACK_LINES,
    SOURCE_CONTEXT_MAX_TOTAL_CHARS,
    SOURCE_CONTEXT_PER_FUNCTION_CHARS,
)


def _read_function_body(codebase_path, node, max_chars=FUNCTION_BODY_DEFAULT_CHARS):
    smap = SourceMap.for_file(codebase_path, node.file_path)
    if smap is None:
        return ""
    return smap.function_slice(
        node.line_number,
        node.end_line,
        max_chars=max_chars,
        fallback_lines=FUNCTION_BODY_FALLBACK_LINES,
    )


def _read_line_context(codebase_path, rel_file, line_number, context=2, max_chars=1200):
    smap = SourceMap.for_file(codebase_path, rel_file)
    if smap is None:
        return ""
    return smap.context_slice(
        int(line_number or 1), radius=context, max_chars=max_chars
    )


def _build_file_grouped_node_chunks(
    codebase_path,
    nodes,
    max_total_chars=SOURCE_CONTEXT_MAX_TOTAL_CHARS,
    per_fn_chars=SOURCE_CONTEXT_PER_FUNCTION_CHARS,
):
    by_file = defaultdict(list)
    for fn in sorted(
        nodes, key=lambda n: (str(n.file_path), int(n.line_number or 0), str(n.name))
    ):
        by_file[fn.file_path].append(fn)

    chunks = []
    current_nodes = []
    current_parts = []
    current_size = 0

    def flush_current():
        nonlocal current_nodes, current_parts, current_size
        if current_parts:
            chunks.append((list(current_nodes), "\n\n".join(current_parts)))
            current_nodes = []
            current_parts = []
            current_size = 0

    for file_path in sorted(by_file):
        header = f"===== FILE: {file_path} ====="
        entries = []
        for fn in by_file[file_path]:
            body = _read_function_body(codebase_path, fn, per_fn_chars)
            if body:
                entries.append(
                    (
                        fn,
                        f"Function {fn.unique_name} (line {fn.line_number} in {fn.file_path}):\n{body}",
                    )
                )
        if not entries:
            continue

        file_nodes = [fn for fn, _ in entries]
        file_text = header + "\n\n" + "\n\n".join(text for _, text in entries)
        if len(file_text) <= max_total_chars:
            if current_size + len(file_text) > max_total_chars and current_parts:
                flush_current()
            current_nodes.extend(file_nodes)
            current_parts.append(file_text)
            current_size += len(file_text)
            continue

        flush_current()
        part_nodes = []
        part_texts = [header]
        part_size = len(header)
        for fn, text in entries:
            entry_size = len(text) + 2
            if part_size + entry_size > max_total_chars and part_nodes:
                chunks.append((part_nodes, "\n\n".join(part_texts)))
                part_nodes = []
                part_texts = [header]
                part_size = len(header)
            part_nodes.append(fn)
            part_texts.append(text)
            part_size += entry_size
        if part_nodes:
            chunks.append((part_nodes, "\n\n".join(part_texts)))

    flush_current()
    return chunks


def _build_file_grouped_chunks(
    codebase_path,
    nodes,
    max_total_chars=SOURCE_CONTEXT_MAX_TOTAL_CHARS,
    per_fn_chars=SOURCE_CONTEXT_PER_FUNCTION_CHARS,
):
    return [
        text
        for _nodes, text in _build_file_grouped_node_chunks(
            codebase_path,
            nodes,
            max_total_chars=max_total_chars,
            per_fn_chars=per_fn_chars,
        )
    ]


def _build_globals_code(graph, max_chars=20000):
    globals_ = sorted(
        graph.get_globals(),
        key=lambda g: (str(g.file_path), int(g.line_number or 0), str(g.name)),
    )
    if not globals_:
        return ""
    parts, total = [], 0
    for g in globals_:
        refs = ", ".join(g.referenced_functions)
        entry = (
            f"GLOBAL {g.unique_name} line {g.line_number}\n"
            f"initializer:\n{g.initializer}\n"
            f"referenced_functions: {refs}"
        )
        if total + len(entry) > max_chars and parts:
            break
        if total + len(entry) > max_chars:
            entry = entry[:max_chars]
        parts.append(entry)
        total += len(entry)
    return "\n\n".join(parts)
