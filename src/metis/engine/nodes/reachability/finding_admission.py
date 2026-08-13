# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Grounded necessary-condition admission for Reachability findings."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from metis.engine.codegraph import CallSite
from metis.engine.codegraph import CodeExpression
from metis.engine.codegraph import CodeGraph

from .domain import VulnerabilityFinding
from .prompt_evidence import _ordered_node_callsites
from .state import FunctionContract
from .state import TrackedObjectSubject
from .state import callsite_has_deterministic_nonnull_return
from .state import expression_modified_between


@dataclass(frozen=True, slots=True)
class _GroundedNecessaryCondition:
    subject: TrackedObjectSubject


@dataclass(frozen=True, slots=True)
class _GroundedNecessaryAlternative:
    sink_call_index: int
    conditions: tuple[_GroundedNecessaryCondition, ...]


def _admitted_finding_ids(
    graph: CodeGraph,
    findings: Mapping[str, VulnerabilityFinding],
    necessary_alternatives: Mapping[
        str,
        tuple[_GroundedNecessaryAlternative, ...],
    ],
    contracts: Mapping[str, FunctionContract],
) -> tuple[frozenset[str], int]:
    admitted: set[str] = set()
    for finding_id, finding in findings.items():
        alternatives = necessary_alternatives.get(finding_id, ())
        if not alternatives:
            admitted.add(finding_id)
            continue
        node = graph.get_node(finding.primary_function)
        if node is None:
            admitted.add(finding_id)
            continue
        calls = _ordered_node_callsites(node)
        all_alternatives_contradicted = True
        for alternative in alternatives:
            if not 0 <= alternative.sink_call_index < len(calls):
                all_alternatives_contradicted = False
                break
            selected_sink = calls[alternative.sink_call_index]
            alternative_contradicted = False
            for condition in alternative.conditions:
                if _condition_is_contradicted(
                    graph,
                    finding,
                    selected_sink,
                    condition,
                    contracts,
                ):
                    alternative_contradicted = True
                    break
            if not alternative_contradicted:
                all_alternatives_contradicted = False
                break
        if all_alternatives_contradicted:
            continue
        admitted.add(finding_id)
    return frozenset(admitted), len(findings) - len(admitted)


def _condition_is_contradicted(
    graph: CodeGraph,
    finding: VulnerabilityFinding,
    selected_sink: CallSite,
    condition: _GroundedNecessaryCondition,
    contracts: Mapping[str, FunctionContract],
) -> bool:
    subject = condition.subject
    node = graph.get_node(subject.function_id)
    if node is None or node.unique_name != finding.primary_function:
        return False
    result_calls = [
        call
        for call in _ordered_node_callsites(node)
        if call.result is not None
        and call.result.start_byte == subject.start_byte
        and call.result.end_byte == subject.end_byte
    ]
    if len(result_calls) != 1:
        return False
    result = result_calls[0].result
    if result is None:
        return False
    if result_calls[0].end_byte >= selected_sink.start_byte:
        return False
    anchor = finding.primary_anchor or {}
    anchor_start = int(anchor.get("start_line") or finding.primary_line)
    anchor_end = int(anchor.get("end_line") or finding.primary_line)
    if not anchor_start <= selected_sink.line <= anchor_end:
        return False
    if not any(
        _expression_matches_result(argument, result)
        for argument in selected_sink.arguments
    ):
        return False
    if expression_modified_between(
        node,
        result,
        start_byte=result_calls[0].end_byte,
        end_byte=selected_sink.start_byte,
    ):
        return False
    for call in _ordered_node_callsites(node):
        if not result_calls[0].end_byte < call.start_byte < selected_sink.start_byte:
            continue
        return False
    return callsite_has_deterministic_nonnull_return(
        node,
        result_calls[0],
        contracts,
    )


def _expression_matches_result(
    expression: CodeExpression,
    result: CodeExpression,
) -> bool:
    return bool(
        result.direct_identifier
        and expression.direct_identifier == result.direct_identifier
        or result.direct_field_path
        and expression.direct_field_path == result.direct_field_path
    )
