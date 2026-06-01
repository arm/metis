# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from .reachability import VulnerabilityFinding
from .reachability.finding_values import (
    _mitigation_text,
    _normalise_vuln_type,
    _safe_int,
    _severity_title,
)
from .reachability.graph_utils import _same_file
from .reachability.source_context import _read_line_context

REACHABILITY_REASONING_METADATA_PREFIXES = (
    "Primary location:",
    "Reviewed file participates via:",
    "Connected functions:",
    "Reachability path:",
    "Root cause:",
    "Analysis type:",
    "Canonical key:",
)


def finding_to_review_item(finding, *, graph=None, codebase_path, target_file=""):
    line_number = int(
        finding.primary_line or finding.sink_line or finding.source_line or 1
    )
    vtype = _normalise_vuln_type(finding.vulnerability_type)
    primary_fn = finding.primary_function or finding.sink_function
    issue = (
        str(finding.description).strip() or f"{vtype.replace('_', ' ')} in {primary_fn}"
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


def review_item_to_finding(item, *, finding_id):
    root_cause, evidence = split_reachability_reasoning(item.get("reasoning"))
    primary_file = str(item.get("primary_file") or "")
    primary_function = str(item.get("primary_function") or "")
    line_number = _safe_int(item.get("line_number"), 0)
    return VulnerabilityFinding(
        finding_id,
        "other",
        str(item.get("severity") or "medium").lower(),
        safe_float(item.get("confidence"), 0.0),
        primary_function,
        primary_file,
        line_number,
        primary_function,
        primary_file,
        line_number,
        path=(
            [str(path_item) for path_item in item.get("path") if path_item]
            if isinstance(item.get("path"), list)
            else []
        ),
        description=str(item.get("issue") or ""),
        root_cause=root_cause,
        evidence=evidence,
        mitigation=str(item.get("mitigation") or ""),
        cwe=str(item.get("cwe") or ""),
        analysis_type=str(item.get("analysis_type") or "reachability"),
        primary_file=primary_file,
        primary_function=primary_function,
        primary_line=line_number,
        canonical_key=str(item.get("canonical_key") or ""),
    )


def review_sort_key(item):
    return (
        {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(item.get("severity"), 4),
        int(item.get("line_number") or 0),
        str(item.get("issue") or ""),
    )


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


def split_reachability_reasoning(reasoning):
    root_cause = ""
    evidence_lines = []
    for raw_line in str(reasoning or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Root cause:"):
            root_cause = line.removeprefix("Root cause:").strip()
            continue
        if line.startswith(REACHABILITY_REASONING_METADATA_PREFIXES):
            continue
        evidence_lines.append(line)
    return root_cause, "\n".join(evidence_lines)


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
