# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from collections import defaultdict

from metis.engine.analysis.c_family_analyzer_common import (
    _identifier_from_node,
    _node_child_by_field_name,
    _node_children,
    _node_kind,
    _node_line,
    _node_text,
)
from metis.engine.analysis.c_family_ast import CFamilyAstMixin
from metis.engine.analysis.treesitter_runtime import TreeSitterRuntime

_LOCK_CALLS = frozenset(
    "pthread_mutex_lock mutex_lock spin_lock spin_lock_irqsave spin_lock_irq".split()
)
_UNLOCK_CALLS = frozenset(
    "pthread_mutex_unlock mutex_unlock spin_unlock spin_unlock_irqrestore "
    "spin_unlock_irq".split()
)


def _normalise_lock_expr(expr):
    expr = "".join(str(expr or "").strip().split()).replace("->", ".")
    for _ in range(4):
        expr = expr.strip("&")
        if not (expr.startswith("(") and ")" in expr):
            break
        close = expr.find(")")
        inner = expr[1:close]
        suffix = expr[close + 1 :]
        if close == len(expr) - 1:
            expr = inner
        elif suffix:
            expr = suffix
        else:
            break
    expr = expr.strip("&()")
    if not expr:
        return ""
    if expr.endswith(".lock"):
        return ".".join(expr.split(".")[-2:])
    return expr


class _TreeSitterLockExtractor(CFamilyAstMixin):
    def __init__(self):
        self._runtimes = {
            "c": TreeSitterRuntime("c"),
            "cpp": TreeSitterRuntime("cpp"),
        }

    def extract_edges(self, graph, codebase_path):
        edges = defaultdict(list)
        for file_path, nodes in _nodes_by_file(graph).items():
            parsed = self._parse_file(
                codebase_path, file_path, _language_for_nodes(nodes)
            )
            if parsed is None:
                continue
            source = bytes(parsed.text, "utf-8")
            by_name_line = defaultdict(list)
            for node in nodes:
                by_name_line[(node.name, int(node.line_number or 0))].append(node)

            for fn_node in self._iter_function_definitions(
                parsed.tree.root_node(), include_methods=True
            ):
                name = self._function_name_from_definition(fn_node, source)
                graph_nodes = by_name_line.get((name, _node_line(fn_node)), [])
                if not graph_nodes:
                    continue
                for graph_node in graph_nodes:
                    _record_lock_edges(
                        edges, graph_node, self._iter_lock_events(fn_node, source)
                    )
        return edges

    def _parse_file(self, codebase_path, file_path, language):
        runtime = self._runtimes.get(language)
        if runtime is None or not runtime.is_available:
            return None
        try:
            return runtime.parse_file(codebase_path, file_path)
        except Exception:
            return None

    def _iter_lock_events(self, function_node, source):
        for call in self._iter_nodes(function_node):
            if _node_kind(call) != "call_expression":
                continue
            callee_node = _field(call, "function")
            callee = _identifier_from_node(callee_node or call, source).lower()
            if callee not in _LOCK_CALLS and callee not in _UNLOCK_CALLS:
                continue
            arg = _first_argument(call)
            lock = _normalise_lock_expr(_node_text(arg, source))
            if lock:
                yield callee, lock, _node_line(call)


def _extract_lock_conflicts(graph, codebase_path):
    edges = _TreeSitterLockExtractor().extract_edges(graph, codebase_path)

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


def _nodes_by_file(graph):
    grouped = defaultdict(list)
    for node in sorted(
        graph.nodes.values(),
        key=lambda item: (item.file_path, item.line_number, item.name),
    ):
        grouped[node.file_path].append(node)
    return grouped


def _record_lock_edges(edges, node, events):
    held = []
    for fn_name, lock, line in events:
        if fn_name in _UNLOCK_CALLS:
            if lock in held:
                held.remove(lock)
            continue
        for prior in held:
            if prior != lock:
                edges[(prior, lock)].append((node, line))
        if lock not in held:
            held.append(lock)


def _first_argument(call_node):
    arguments = _field(call_node, "arguments")
    if arguments is None:
        return None
    for child in _node_children(arguments):
        if _node_kind(child) not in {"(", ")", ",", "comment"}:
            return child
    return None


def _field(node, name):
    return _node_child_by_field_name(node, name)


def _language_for_nodes(nodes):
    for node in nodes:
        language = str(getattr(node, "language", "") or "").lower()
        if language:
            return language
    return "c"
