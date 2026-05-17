# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Deterministic lock-order candidate extraction for reachability review."""

from __future__ import annotations

import re
from collections import defaultdict

from .source_context import _read_function_body

_LOCK_EVENT_RE = re.compile(
    r"\b(?P<fn>pthread_mutex_lock|pthread_mutex_unlock|mutex_lock|mutex_unlock|"
    r"spin_lock(?:_irqsave|_irq)?|spin_unlock(?:_irqrestore|_irq)?)\s*"
    r"\(\s*(?P<arg>[^,\)]+)",
    re.IGNORECASE,
)


def _normalise_lock_expr(expr):
    expr = re.sub(r"/\*.*?\*/", "", str(expr or ""))
    expr = re.sub(r"\s+", "", expr).strip("&()")
    expr = re.sub(r"^\([^)]*\)", "", expr)
    expr = expr.replace("->", ".").strip("&()")
    if not expr:
        return ""
    if expr.endswith(".lock"):
        return ".".join(expr.split(".")[-2:])
    return expr


def _extract_lock_conflicts(graph, codebase_path):
    edges = defaultdict(list)
    for node in sorted(
        graph.nodes.values(), key=lambda n: (n.file_path, n.line_number, n.name)
    ):
        body = _read_function_body(codebase_path, node, 8000)
        if not body:
            continue
        held = []
        for match in _LOCK_EVENT_RE.finditer(body):
            lock = _normalise_lock_expr(match.group("arg"))
            if not lock:
                continue
            line = node.line_number + body[: match.start()].count("\n")
            fn_name = match.group("fn").lower()
            if "unlock" in fn_name:
                if lock in held:
                    held.remove(lock)
                continue
            for prior in held:
                if prior != lock:
                    edges[(prior, lock)].append((node, line))
            if lock not in held:
                held.append(lock)

    conflicts, seen = [], set()
    for (a, b), first_edges in edges.items():
        reverse_edges = edges.get((b, a))
        if not reverse_edges:
            continue
        for node_a, line_a in first_edges:
            for node_b, line_b in reverse_edges:
                if node_a.unique_name == node_b.unique_name:
                    continue
                key = tuple(
                    sorted((node_a.unique_name, node_b.unique_name)) + sorted((a, b))
                )
                if key in seen:
                    continue
                seen.add(key)
                conflicts.append((a, b, node_a, line_a, node_b, line_b))
                if len(conflicts) >= 40:
                    return conflicts
    return conflicts
