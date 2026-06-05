# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Parse supplementary lens model output into reachability findings.

Supplementary lenses ask the model different questions over different graph
scopes. This module keeps the response-shape differences out of
``supplementary.py`` and converts every accepted entry into the common
``VulnerabilityFinding`` shape used by finalization and review rendering.
"""

from collections.abc import Sequence
from typing import Any

from .finding_builder import _finding_from_llm_entry, _lookup_fn
from .llm_runner import reachability_response_payload
from .domain import FunctionNode, VulnerabilityFinding

type FunctionIndexes = tuple[dict[str, FunctionNode], dict[str, FunctionNode]]


def _finding_entries(raw: object) -> list[dict[str, Any]]:
    parsed = reachability_response_payload(raw)
    if not isinstance(parsed, dict):
        return []
    findings = parsed.get("findings")
    if not isinstance(findings, list):
        return []
    return [entry for entry in findings if isinstance(entry, dict)]


def _parse_intra(
    raw: object,
    functions: Sequence[FunctionNode],
    analysis_type: str = "intra_function",
) -> list[VulnerabilityFinding]:
    if not functions:
        return []
    indexes = _function_indexes(functions)
    results: list[VulnerabilityFinding] = []
    for entry in _finding_entries(raw):
        fn = _lookup_in_functions(entry.get("function_name"), indexes, functions)
        if not fn:
            # The intra prompt is scoped to this function batch, so a missing
            # name is still useful. Preserve the existing behavior by assigning
            # it to the first shown function rather than dropping it here.
            fn = functions[0]
        line = _entry_line(entry, fn.line_number)
        results.append(
            _finding_from_llm_entry(
                entry,
                fn.unique_name,
                fn.file_path,
                line,
                fn.unique_name,
                fn.file_path,
                line,
                [fn.unique_name],
                analysis_type,
            )
        )
    return results


def _parse_combined(
    raw: object,
    all_fns: Sequence[FunctionNode],
    allowed_analysis_types: frozenset[str],
) -> list[VulnerabilityFinding]:
    indexes = _function_indexes(all_fns)
    results: list[VulnerabilityFinding] = []
    for entry in _finding_entries(raw):
        analysis_type = (
            str(entry.get("analysis_type") or "").strip().lower().replace("-", "_")
        )
        if analysis_type not in allowed_analysis_types:
            continue

        source_name, sink_name = _combined_source_sink_names(entry, analysis_type)
        sink_fn = _lookup_in_functions(sink_name, indexes, all_fns)
        source_fn = _lookup_in_functions(source_name, indexes, all_fns)
        if not sink_fn:
            continue
        if not source_fn:
            source_fn = sink_fn
        high_risk_cross = analysis_type in {"lifecycle", "ownership"}
        results.append(
            _finding_from_llm_entry(
                entry,
                source_fn.unique_name,
                source_fn.file_path,
                source_fn.line_number,
                sink_fn.unique_name,
                sink_fn.file_path,
                sink_fn.line_number,
                (
                    [source_fn.unique_name, sink_fn.unique_name]
                    if source_fn.unique_name != sink_fn.unique_name
                    else [sink_fn.unique_name]
                ),
                analysis_type,
                default_vulnerability_type=(
                    "use_after_free" if high_risk_cross else "other"
                ),
                default_severity="high" if high_risk_cross else "medium",
            )
        )
    return results


def _parse_semantic(
    raw: object,
    all_fns: Sequence[FunctionNode],
    analysis_type: str = "semantic",
) -> list[VulnerabilityFinding]:
    indexes = _function_indexes(all_fns)
    results: list[VulnerabilityFinding] = []
    for entry in _finding_entries(raw):
        fn = _lookup_in_functions(entry.get("function_name"), indexes, all_fns)
        rf = _lookup_in_functions(entry.get("related_function"), indexes, all_fns)
        if not fn:
            continue
        src_fn = rf or fn
        results.append(
            _finding_from_llm_entry(
                entry,
                src_fn.unique_name,
                src_fn.file_path,
                src_fn.line_number,
                fn.unique_name,
                fn.file_path,
                fn.line_number,
                [src_fn.unique_name, fn.unique_name] if rf else [fn.unique_name],
                analysis_type,
            )
        )
    return results


def _function_indexes(functions: Sequence[FunctionNode]) -> FunctionIndexes:
    return (
        {fn.name: fn for fn in functions},
        {fn.unique_name: fn for fn in functions},
    )


def _lookup_in_functions(
    value: object,
    indexes: FunctionIndexes,
    functions: Sequence[FunctionNode],
) -> FunctionNode | None:
    by_name, by_unique = indexes
    return _lookup_fn(str(value or ""), by_name, by_unique, functions)


def _entry_line(entry: dict[str, Any], default: int) -> int:
    try:
        return max(1, int(entry.get("line", default)))
    except (TypeError, ValueError):
        return default


def _combined_source_sink_names(
    entry: dict[str, Any],
    analysis_type: str,
) -> tuple[object, object]:
    if analysis_type == "lifecycle":
        return (
            entry.get("free_function")
            or entry.get("teardown_function")
            or entry.get("source_function")
            or entry.get("related_function"),
            entry.get("use_function")
            or entry.get("sink_function")
            or entry.get("primary_function")
            or entry.get("function_name"),
        )
    if analysis_type == "ownership":
        return (
            entry.get("function_a")
            or entry.get("source_function")
            or entry.get("related_function"),
            entry.get("function_b")
            or entry.get("sink_function")
            or entry.get("primary_function")
            or entry.get("function_name"),
        )
    return (
        entry.get("related_function") or entry.get("source_function"),
        entry.get("function_name")
        or entry.get("sink_function")
        or entry.get("primary_function"),
    )
