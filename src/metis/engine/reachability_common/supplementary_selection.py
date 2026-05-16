# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Candidate selection helpers for supplementary reachability lenses."""

from __future__ import annotations

import re
from collections import defaultdict

from .source_context import _read_function_body


def _node_match_text(codebase_path, node, max_chars=12000):
    body = _read_function_body(codebase_path, node, max_chars)
    return f"{node.name}\n{' '.join(node.calls)}\n{body}"


def _select_nodes_by_regex(
    graph, codebase_path, pattern, *, max_body_chars=12000, extra_keywords=()
):
    nodes = []
    keywords = tuple(str(k).lower() for k in extra_keywords if str(k).strip())
    for node in sorted(
        graph.nodes.values(), key=lambda n: (n.file_path, n.line_number, n.name)
    ):
        text = _node_match_text(codebase_path, node, max_body_chars)
        if pattern.search(text) or (
            keywords and any(keyword in text.lower() for keyword in keywords)
        ):
            nodes.append(node)
    return nodes


def _function_name_tokens(name):
    return [t for t in re.split(r"[^a-z0-9]+", str(name or "").lower()) if t]


def _related_function_score(seed_nodes, node, relation_keywords):
    name_l = str(node.name or "").lower()
    if not any(k in name_l for k in relation_keywords):
        return 0

    node_tokens = set(_function_name_tokens(node.name))
    node_stem = node_tokens - set(relation_keywords)
    score = 0
    nearest = None
    for seed in seed_nodes:
        seed_tokens = set(_function_name_tokens(seed.name))
        seed_stem = seed_tokens - set(relation_keywords)
        shared_stem = node_stem & seed_stem
        if shared_stem:
            score = max(score, 10 + len(shared_stem) * 3)
        elif seed_tokens and node_tokens and sorted(seed_tokens)[0] in node_tokens:
            score = max(score, 4)
        distance = abs(int(node.line_number or 0) - int(seed.line_number or 0))
        nearest = distance if nearest is None else min(nearest, distance)
    if score and nearest is not None and nearest <= 160:
        score += max(1, 8 - nearest // 20)
    return score


def _expand_candidates_with_related_file_functions(
    graph, candidates, relation_keywords, max_extra_per_file=8
):
    """Add a capped set of same-file lifecycle/accounting siblings for local context."""
    if not candidates:
        return []
    relation_keywords = frozenset(
        str(k).lower() for k in relation_keywords if str(k).strip()
    )
    if not relation_keywords:
        return list(candidates)

    selected = {node.unique_name: node for node in candidates}
    by_file = defaultdict(list)
    for node in candidates:
        by_file[node.file_path].append(node)

    for file_path, seed_nodes in by_file.items():
        scored = []
        for node in graph.get_file_nodes(file_path):
            if node.unique_name in selected:
                continue
            score = _related_function_score(seed_nodes, node, relation_keywords)
            if score <= 0:
                continue
            nearest = min(
                abs(int(node.line_number or 0) - int(seed.line_number or 0))
                for seed in seed_nodes
            )
            scored.append(
                (-score, nearest, int(node.line_number or 0), node.name, node)
            )
        for _, _, _, _, node in sorted(scored)[:max_extra_per_file]:
            selected[node.unique_name] = node

    return sorted(
        selected.values(), key=lambda n: (n.file_path, int(n.line_number or 0), n.name)
    )
