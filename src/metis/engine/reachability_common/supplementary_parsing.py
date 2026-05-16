# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""JSON parsing for supplementary reachability lens output."""

from __future__ import annotations

from metis.utils import parse_json_output

from .finding_normalization import (
    _finding_from_llm_entry,
    _lookup_fn,
)
from .supplementary_lenses import _COMBINED_GRAPH_ANALYSIS_TYPE_ALIASES


def _finding_entries(raw):
    parsed = parse_json_output(raw)
    if not isinstance(parsed, dict):
        return []
    fl = parsed.get("findings")
    return fl if isinstance(fl, list) else []


def _parse_intra(raw, functions, analysis_type="intra_function"):
    fl = _finding_entries(raw)
    lk = {fn.name: fn for fn in functions}
    bu = {f.unique_name: f for f in functions}
    results = []
    for entry in fl:
        if not isinstance(entry, dict):
            continue
        fn = _lookup_fn(str(entry.get("function_name") or ""), lk, bu, functions)
        if not fn:
            fn = functions[0]
        line = fn.line_number
        try:
            line = max(1, int(entry.get("line", line)))
        except (TypeError, ValueError):
            pass
        results.append(
            _finding_from_llm_entry(
                entry,
                source_function=fn.unique_name,
                source_file=fn.file_path,
                source_line=line,
                sink_function=fn.unique_name,
                sink_file=fn.file_path,
                sink_line=line,
                path=[fn.unique_name],
                analysis_type=analysis_type,
            )
        )
    return results


def _normalise_combined_analysis_type(value, allowed_analysis_types):
    raw = str(value or "").strip().lower().replace("-", "_")
    if raw in allowed_analysis_types:
        return raw
    alias = _COMBINED_GRAPH_ANALYSIS_TYPE_ALIASES.get(raw)
    if alias in allowed_analysis_types:
        return alias
    return ""


def _parse_combined(raw, all_fns, allowed_analysis_types):
    fl = _finding_entries(raw)
    bn = {fn.name: fn for fn in all_fns}
    bu = {fn.unique_name: fn for fn in all_fns}
    results = []
    for entry in fl:
        if not isinstance(entry, dict):
            continue
        analysis_type = _normalise_combined_analysis_type(
            entry.get("analysis_type"), allowed_analysis_types
        )
        if not analysis_type:
            continue

        if analysis_type == "lifecycle":
            source_name = (
                entry.get("free_function")
                or entry.get("teardown_function")
                or entry.get("source_function")
                or entry.get("related_function")
            )
            sink_name = (
                entry.get("use_function")
                or entry.get("sink_function")
                or entry.get("primary_function")
                or entry.get("function_name")
            )
        elif analysis_type == "ownership":
            source_name = (
                entry.get("function_a")
                or entry.get("source_function")
                or entry.get("related_function")
            )
            sink_name = (
                entry.get("function_b")
                or entry.get("sink_function")
                or entry.get("primary_function")
                or entry.get("function_name")
            )
        else:
            source_name = entry.get("related_function") or entry.get("source_function")
            sink_name = (
                entry.get("function_name")
                or entry.get("sink_function")
                or entry.get("primary_function")
            )

        sink_fn = _lookup_fn(str(sink_name or ""), bn, bu, all_fns)
        source_fn = _lookup_fn(str(source_name or ""), bn, bu, all_fns)
        if not sink_fn:
            continue
        if not source_fn:
            source_fn = sink_fn
        high_risk_cross = analysis_type in {"lifecycle", "ownership"}
        results.append(
            _finding_from_llm_entry(
                entry,
                source_function=source_fn.unique_name,
                source_file=source_fn.file_path,
                source_line=source_fn.line_number,
                sink_function=sink_fn.unique_name,
                sink_file=sink_fn.file_path,
                sink_line=sink_fn.line_number,
                path=(
                    [source_fn.unique_name, sink_fn.unique_name]
                    if source_fn.unique_name != sink_fn.unique_name
                    else [sink_fn.unique_name]
                ),
                analysis_type=analysis_type,
                default_vulnerability_type=(
                    "use_after_free" if high_risk_cross else "other"
                ),
                default_severity="high" if high_risk_cross else "medium",
            )
        )
    return results


def _parse_semantic(raw, all_fns, analysis_type="semantic"):
    fl = _finding_entries(raw)
    bn = {fn.name: fn for fn in all_fns}
    bu = {fn.unique_name: fn for fn in all_fns}
    results = []
    for entry in fl:
        if not isinstance(entry, dict):
            continue
        fn = _lookup_fn(str(entry.get("function_name") or ""), bn, bu, all_fns)
        rf = _lookup_fn(str(entry.get("related_function") or ""), bn, bu, all_fns)
        if not fn:
            continue
        src_fn = rf or fn
        results.append(
            _finding_from_llm_entry(
                entry,
                source_function=src_fn.unique_name,
                source_file=src_fn.file_path,
                source_line=src_fn.line_number,
                sink_function=fn.unique_name,
                sink_file=fn.file_path,
                sink_line=fn.line_number,
                path=([src_fn.unique_name, fn.unique_name] if rf else [fn.unique_name]),
                analysis_type=analysis_type,
            )
        )
    return results
