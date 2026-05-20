# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Review JSON shaping for tree-sitter reachability findings."""

from __future__ import annotations

import os

from .finding_normalization import (
    _mitigation_text,
    _normalise_vuln_type,
    _severity_title,
)
from .graph_utils import _same_file
from .source_context import _read_line_context


def group_findings_as_reviews(findings, graph, *, codebase_path):
    by_file = {}
    for finding in findings:
        primary_file = finding.primary_file or finding.sink_file or finding.source_file
        if primary_file:
            by_file.setdefault(primary_file, []).append(finding)

    reviews = []
    for target_file in sorted(by_file):
        items = reviews_for_findings(
            by_file[target_file],
            graph,
            codebase_path=codebase_path,
            target_file=target_file,
        )
        if items:
            reviews.append(
                {
                    "file": target_file,
                    "file_path": os.path.join(codebase_path, target_file),
                    "reviews": items,
                }
            )
    return reviews


def reviews_for_findings(findings, graph, *, codebase_path, target_file):
    reviews = [
        finding_to_review(
            finding,
            graph=graph,
            codebase_path=codebase_path,
            target_file=target_file,
        )
        for finding in findings
    ]
    reviews.sort(key=review_sort_key)
    return reviews


def review_sort_key(item):
    return (
        {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(item.get("severity"), 4),
        int(item.get("line_number") or 0),
        str(item.get("issue") or ""),
    )


def finding_to_review(finding, *, graph=None, codebase_path, target_file=""):
    line_number = int(
        finding.primary_line or finding.sink_line or finding.source_line or 1
    )
    vtype = _normalise_vuln_type(finding.vulnerability_type)
    primary_fn = finding.primary_function or finding.sink_function
    issue = str(finding.description).strip() or (
        f"{vtype.replace('_', ' ')} in {primary_fn}"
    )
    primary_file = finding.primary_file or finding.sink_file or finding.source_file
    reasoning_parts = []
    if primary_file:
        reasoning_parts.append(
            f"Primary location: {primary_file}:{line_number}"
            + (f" ({primary_fn})" if primary_fn else "")
        )
    if target_file and not _same_file(primary_file, target_file):
        reasoning_parts.append(f"Reviewed file participates via: {target_file}")
    connected = connected_functions_for_finding(finding, graph, target_file)
    if connected:
        reasoning_parts.append(f"Connected functions: {', '.join(connected[:8])}")
    if str(finding.evidence or "").strip():
        reasoning_parts.append(str(finding.evidence).strip())
    if finding.path:
        reasoning_parts.append(f"Reachability path: {' -> '.join(finding.path)}")
    if str(finding.root_cause or "").strip():
        reasoning_parts.append(f"Root cause: {str(finding.root_cause).strip()}")
    if finding.analysis_type:
        reasoning_parts.append(f"Analysis type: {finding.analysis_type}")
    if finding.canonical_key:
        reasoning_parts.append(f"Canonical key: {finding.canonical_key}")
    target_file = primary_file
    return {
        "issue": issue,
        "line_number": line_number,
        "primary_file": primary_file,
        "primary_function": primary_fn,
        "analysis_type": finding.analysis_type,
        "path": list(finding.path or []),
        "code_snippet": (
            _read_line_context(codebase_path, primary_file, line_number, context=2)
            if primary_file
            else ""
        ),
        "cwe": str(getattr(finding, "cwe", "") or ""),
        "severity": _severity_title(finding.severity, "Medium"),
        "confidence": finding.confidence,
        "reasoning": "\n".join(reasoning_parts),
        "mitigation": _mitigation_text(finding, vtype),
    }


def connected_functions_for_finding(finding, graph, target_file):
    if graph is None:
        return []
    connected = []
    seen = set()
    candidates = list(finding.path or [])
    candidates.extend(
        [
            finding.primary_function,
            finding.source_function,
            finding.sink_function,
        ]
    )
    for node_name in candidates:
        node = graph.get_node(node_name)
        if not node:
            continue
        for resolved_name in node.resolved_calls or []:
            resolved = graph.get_node(resolved_name)
            if not resolved:
                continue
            if target_file and _same_file(resolved.file_path, target_file):
                continue
            if resolved.unique_name in seen:
                continue
            seen.add(resolved.unique_name)
            connected.append(resolved.unique_name)
    return connected
