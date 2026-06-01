# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import uuid

from .finding_identity import _canonical_fields
from .finding_values import _confidence_score, _normalise_vuln_type
from .domain import VulnerabilityFinding


def _lookup_fn(name, fn_by_name, fn_by_unique, all_fns):
    if not name:
        return None
    if name in fn_by_unique:
        return fn_by_unique[name]
    if name in fn_by_name:
        return fn_by_name[name]
    for fn in all_fns:
        if name in fn.name or name in fn.unique_name:
            return fn
    return None


def _finding_from_llm_entry(
    entry,
    source_function,
    source_file,
    source_line,
    sink_function,
    sink_file,
    sink_line,
    path,
    analysis_type,
    *,
    default_file=None,
    default_function=None,
    default_line=None,
    default_vulnerability_type="other",
    default_severity="medium",
):
    vulnerability_type = _normalise_vuln_type(
        entry.get("vulnerability_type") or default_vulnerability_type
    )
    primary_file, primary_function, primary_line, canonical_key = _canonical_fields(
        entry,
        default_file=sink_file if default_file is None else default_file,
        default_function=(
            sink_function if default_function is None else default_function
        ),
        default_line=sink_line if default_line is None else default_line,
        vulnerability_type=vulnerability_type,
    )
    return VulnerabilityFinding(
        uuid.uuid4().hex[:16],
        vulnerability_type,
        str(entry.get("severity") or default_severity),
        _confidence_score(entry.get("confidence")),
        source_function,
        source_file,
        source_line,
        sink_function,
        sink_file,
        sink_line,
        path=list(path),
        description=str(entry.get("description") or ""),
        root_cause=str(entry.get("root_cause") or ""),
        evidence=str(entry.get("evidence") or ""),
        mitigation=str(entry.get("mitigation") or ""),
        cwe=str(entry.get("cwe") or entry.get("cwe_id") or ""),
        analysis_type=analysis_type,
        primary_file=primary_file,
        primary_function=primary_function,
        primary_line=primary_line,
        canonical_key=canonical_key,
    )
