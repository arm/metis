# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Pure prompt-evidence serialization for incremental Reachability review."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from collections.abc import Sequence
from functools import partial
from typing import Any

from metis.engine.codegraph import CallSite
from metis.engine.codegraph import CodeExpression
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import ControlCondition
from metis.engine.codegraph import FunctionNode
from metis.engine.codegraph import LoopStructure
from metis.engine.codegraph import NullFact
from metis.engine.codegraph import ReturnSite
from metis.engine.codegraph import ValueAssignment
from metis.engine.source import SourceMap

from .graph_utils import _node_sort_key
from .state import FunctionContract
from .state import GuardedTransfer
from .state import ParameterSubject
from .state import ReturnSubject
from .state import SecuritySubject
from .state import TrackedObjectSubject

_NUMBERED_LINE = re.compile(r"^\s*(\d+):", re.MULTILINE)


def _sparse_prompt_data(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            key: _sparse_prompt_data(item)
            for key, item in value.items()
            if item is not None
            and item != ""
            and not (isinstance(item, (Mapping, list, tuple)) and not item)
        }
    if isinstance(value, (list, tuple)):
        return [_sparse_prompt_data(item) for item in value]
    return value


def _prompt_json(value: object) -> str:
    return json.dumps(
        _sparse_prompt_data(value),
        sort_keys=True,
        separators=(",", ":"),
    )


def _shown_lines(source_text: str) -> frozenset[int]:
    return frozenset(int(match) for match in _NUMBERED_LINE.findall(source_text))


def _evidence_file_path(
    graph: CodeGraph,
    value: Mapping[object, object],
    *,
    owning_file_path: str,
) -> str:
    explicit_file_path = value.get("file_path")
    if isinstance(explicit_file_path, str):
        return explicit_file_path
    function_id = value.get("function_id")
    if isinstance(function_id, str) and (node := graph.get_node(function_id)):
        return node.file_path
    return owning_file_path


def _source_span_replacement(
    value: Mapping[object, object],
    *,
    source_map: SourceMap,
    complete_lines: frozenset[int],
) -> tuple[frozenset[str], tuple[int, int] | None]:
    start_byte = value.get("start_byte")
    end_byte = value.get("end_byte")
    if not isinstance(start_byte, int) or not isinstance(end_byte, int):
        return frozenset(), None
    if start_byte < 0 or end_byte <= start_byte:
        return frozenset(), None
    start_line = source_map.byte_to_line(start_byte)
    end_line = source_map.byte_to_line(end_byte - 1)
    if (
        start_line != end_line
        or value.get("line") != start_line
        or start_line not in complete_lines
    ):
        return frozenset(), None
    source_text = source_map.byte_slice(start_byte, end_byte)
    omitted_fields = frozenset(
        field for field in ("text", "expression") if value.get(field) == source_text
    )
    line_start_byte = source_map.line_to_byte(start_line)
    start_column = len(source_map.byte_slice(line_start_byte, start_byte))
    columns = (start_column, start_column + len(source_text))
    removed_size = sum(
        len(json.dumps({field: source_text}, separators=(",", ":"))) - 2
        for field in omitted_fields
    )
    replacement_size = len(json.dumps({"cols": columns}, separators=(",", ":"))) - 2
    if replacement_size >= removed_size:
        return frozenset(), None
    return omitted_fields, columns


def _source_span_prompt_data(
    graph: CodeGraph,
    value: object,
    *,
    source_map: SourceMap,
    file_path: str,
    complete_lines: frozenset[int],
    owning_file_path: str,
) -> object:
    if isinstance(value, Mapping):
        mapped_file_path = _evidence_file_path(
            graph,
            value,
            owning_file_path=owning_file_path,
        )
        result = {
            key: _source_span_prompt_data(
                graph,
                item,
                source_map=source_map,
                file_path=file_path,
                complete_lines=complete_lines,
                owning_file_path=mapped_file_path,
            )
            for key, item in value.items()
        }
        if mapped_file_path != file_path:
            return result
        omitted_fields, source_columns = _source_span_replacement(
            value,
            source_map=source_map,
            complete_lines=complete_lines,
        )
        if source_columns is None:
            return result
        return {
            **{
                key: item
                for key, item in result.items()
                if key not in omitted_fields | {"start_byte", "end_byte"}
            },
            "cols": list(source_columns),
        }
    if isinstance(value, (list, tuple)):
        return [
            _source_span_prompt_data(
                graph,
                item,
                source_map=source_map,
                file_path=file_path,
                complete_lines=complete_lines,
                owning_file_path=owning_file_path,
            )
            for item in value
        ]
    return value


def _compact_source_evidence(
    graph: CodeGraph,
    value: object,
    *,
    codebase_path: str,
    file_path: str,
    source_text: str,
) -> object:
    source_map = SourceMap.for_file(codebase_path, file_path)
    if source_map is None:
        return value
    complete_line_numbers: set[int] = set()
    for rendered_line in source_text.splitlines():
        match = re.fullmatch(r"\s*(\d+): (.*)", rendered_line)
        if match is None:
            continue
        line_number = int(match.group(1))
        if (
            line_number <= source_map.line_count
            and match.group(2) == source_map.lines[line_number - 1]
        ):
            complete_line_numbers.add(line_number)
    complete_lines = frozenset(complete_line_numbers)
    if not complete_lines:
        return value
    return _source_span_prompt_data(
        graph,
        value,
        source_map=source_map,
        file_path=file_path,
        complete_lines=complete_lines,
        owning_file_path=file_path,
    )


def _expression_data(expression: CodeExpression) -> dict[str, object]:
    return {
        "text": expression.text,
        "line": expression.line,
        "start_byte": expression.start_byte,
        "end_byte": expression.end_byte,
        "identifiers": list(expression.identifiers),
        "field_paths": list(expression.field_paths),
        "direct_identifier": expression.direct_identifier,
        "direct_field_path": expression.direct_field_path,
    }


def _condition_data(condition: ControlCondition) -> dict[str, object]:
    return {
        "expression": _expression_data(condition.expression),
        "truth": condition.truth,
        "null_condition": (
            {
                "when_true": [
                    _null_fact_data(fact) for fact in condition.null_condition.when_true
                ],
                "when_false": [
                    _null_fact_data(fact)
                    for fact in condition.null_condition.when_false
                ],
            }
            if condition.null_condition is not None
            else None
        ),
    }


def _null_fact_data(fact: NullFact) -> dict[str, object]:
    return {
        "value": _expression_data(fact.value),
        "is_null": fact.is_null,
    }


def _assignment_data(assignment: ValueAssignment) -> dict[str, object]:
    return {
        "target": _expression_data(assignment.target),
        "value": _expression_data(assignment.value),
        "operator": assignment.operator,
        "line": assignment.line,
        "start_byte": assignment.start_byte,
        "end_byte": assignment.end_byte,
        "conditions": [_condition_data(item) for item in assignment.conditions],
    }


def _loop_data(loop: LoopStructure) -> dict[str, object]:
    return {
        "condition": (
            _expression_data(loop.condition) if loop.condition is not None else None
        ),
        "line": loop.line,
        "start_byte": loop.start_byte,
        "end_byte": loop.end_byte,
        "written_identifiers": list(loop.written_identifiers),
        "addressed_identifiers": list(loop.addressed_identifiers),
        "condition_identifiers_written": sorted(
            set(loop.condition.identifiers if loop.condition is not None else ())
            & set(loop.written_identifiers)
        ),
    }


def _return_data(return_site: ReturnSite) -> dict[str, object]:
    return {
        "value": (
            _expression_data(return_site.value)
            if return_site.value is not None
            else None
        ),
        "line": return_site.line,
        "start_byte": return_site.start_byte,
        "end_byte": return_site.end_byte,
        "conditions": [_condition_data(item) for item in return_site.conditions],
        "returns_null": return_site.returns_null,
    }


def _call_expression_data(call: CallSite) -> dict[str, object]:
    return {
        "arguments": [_expression_data(item) for item in call.arguments],
        "conditions": [_condition_data(item) for item in call.conditions],
        "must_conditions": [_condition_data(item) for item in call.must_conditions],
        "result": _expression_data(call.result) if call.result is not None else None,
    }


def _tag_data(
    node: FunctionNode,
    *,
    include_syntax_tags: bool = False,
) -> list[dict[str, str]]:
    return [
        {
            "name": name,
            "value": tag.value,
            "reason": tag.reason,
        }
        for name, tag in sorted(node.tags.items())
        if include_syntax_tags or not name.startswith("syntax.")
    ]


def _call_target_facts(
    graph: CodeGraph,
    call: CallSite,
    *,
    include_syntax_tags: bool,
) -> list[dict[str, object]]:
    facts: list[dict[str, object]] = []
    for target_id in call.target_ids:
        target = graph.get_node(target_id)
        if target is None:
            continue
        tags = _tag_data(target, include_syntax_tags=include_syntax_tags)
        if not tags:
            continue
        facts.append(
            {
                "function_id": target.unique_name,
                "tags": tags,
            }
        )
    return facts


def _boundary_call_data(
    graph: CodeGraph,
    call: CallSite,
    *,
    include_syntax_tags: bool,
) -> dict[str, object]:
    return {
        "line": call.line,
        "start_byte": call.start_byte,
        "end_byte": call.end_byte,
        "symbol": call.symbol,
        "kind": call.kind,
        "argument_count": call.argument_count,
        "resolution": call.resolution,
        "target_ids": list(call.target_ids),
        "targets_complete": call.targets_complete,
        "target_facts": _call_target_facts(
            graph,
            call,
            include_syntax_tags=include_syntax_tags,
        ),
        **_call_expression_data(call),
    }


def _codegraph_evidence_data(
    graph: CodeGraph,
    nodes: Sequence[FunctionNode],
    contracts: Mapping[str, FunctionContract] | None = None,
    *,
    shown_lines: frozenset[int] | None = None,
) -> dict[str, object]:
    contract_map = contracts or {}
    ordered_nodes = tuple(
        sorted(
            (graph.nodes.get(node.unique_name, node) for node in nodes),
            key=partial(_node_sort_key, graph),
        )
    )
    current_ids = {node.unique_name for node in ordered_nodes}
    direct_edges = sorted(
        {
            (node.unique_name, target_id)
            for node in ordered_nodes
            for target_id in node.resolved_calls
            if target_id in graph.nodes
        }
    )
    direct_nodes = [
        graph.nodes[node_id]
        for node_id in sorted(
            {target_id for _caller_id, target_id in direct_edges},
            key=partial(_node_sort_key, graph),
        )
        if node_id not in current_ids
    ]
    direct_contract_ids = tuple(
        sorted(
            {target_id for _caller_id, target_id in direct_edges},
            key=partial(_node_sort_key, graph),
        )
    )
    return {
        "functions": [_discovery_function_data(graph, node) for node in ordered_nodes],
        "call_results": _call_result_data(
            graph,
            tuple(node.unique_name for node in ordered_nodes),
            shown_lines=shown_lines,
        ),
        "direct_edges": [list(edge) for edge in direct_edges],
        "direct_functions": [
            {
                **_function_boundary_data(graph, node, include_syntax_tags=True),
                "graph_entrypoint_candidate": node.is_public_entrypoint,
            }
            for node in direct_nodes
        ],
        "direct_function_contracts": [
            _direct_contract_data(contract_map[node_id])
            for node_id in direct_contract_ids
            if node_id in contract_map
        ],
    }


def _direct_contract_data(contract: FunctionContract) -> dict[str, object]:
    return {
        "function": contract.function_id,
        "normal_return_transfers": [
            _guarded_transfer_data(transfer)
            for transfer in contract.normal_return_transfers
        ],
        "normal_exit": {
            "status": contract.normal_exit.status,
            "origin": contract.normal_exit.origin,
            "line": contract.normal_exit.evidence_line,
        },
    }


def _guarded_transfer_data(transfer: GuardedTransfer) -> dict[str, object]:
    return {
        "requirements": [
            {
                "atom": {
                    "subject": _subject_model_data(item.atom.subject),
                    "predicate": item.atom.predicate,
                },
                "truth": item.truth,
                "line": item.evidence_line,
                "origin": item.origin,
            }
            for item in transfer.requirements
        ],
        "effects": [
            {
                "operation": item.operation,
                "atom": {
                    "subject": _subject_model_data(item.atom.subject),
                    "predicate": item.atom.predicate,
                },
                "origin": item.origin,
                "line": item.evidence_line,
            }
            for item in transfer.effects
        ],
    }


def _ordered_node_callsites(node: FunctionNode) -> tuple[CallSite, ...]:
    return tuple(
        sorted(
            node.call_sites,
            key=lambda call: (
                call.start_byte,
                call.end_byte,
                call.line,
                call.symbol,
            ),
        )
    )


def _function_boundary_data(
    graph: CodeGraph,
    node: FunctionNode,
    *,
    include_syntax_tags: bool = False,
) -> dict[str, object]:
    return {
        "function_id": node.unique_name,
        "file_path": node.file_path,
        "start_line": node.line_number,
        "end_line": node.end_line or node.line_number,
        "parameter_count": node.parameter_count,
        "parameters": [
            {
                "name": parameter.name,
                "type_spelling": parameter.type_spelling,
            }
            for parameter in node.parameters
        ],
        "tags": _tag_data(node, include_syntax_tags=include_syntax_tags),
        "calls": [
            {
                "call_index": call_index,
                **_boundary_call_data(
                    graph,
                    call,
                    include_syntax_tags=include_syntax_tags,
                ),
            }
            for call_index, call in enumerate(_ordered_node_callsites(node))
        ],
    }


def _discovery_function_data(
    graph: CodeGraph,
    node: FunctionNode,
) -> dict[str, object]:
    return {
        **_function_boundary_data(graph, node, include_syntax_tags=True),
        "graph_entrypoint_candidate": node.is_public_entrypoint,
        "assignments": [_assignment_data(item) for item in node.assignments],
        "loops": [_loop_data(item) for item in node.loops],
        "returns": [_return_data(item) for item in node.returns],
    }


def _call_result_data(
    graph: CodeGraph,
    node_ids: Sequence[str],
    *,
    shown_lines: frozenset[int] | None = None,
) -> list[dict[str, object]]:
    return [
        {
            "call_result_index": call_result_index,
            **grounding,
        }
        for call_result_index, (_subject, grounding) in enumerate(
            _call_result_entries(graph, node_ids, shown_lines=shown_lines)
        )
    ]


def _call_result_entries(
    graph: CodeGraph,
    node_ids: Sequence[str],
    *,
    shown_lines: frozenset[int] | None,
) -> tuple[tuple[TrackedObjectSubject, dict[str, object]], ...]:
    results: list[tuple[TrackedObjectSubject, dict[str, object]]] = []
    for node_id in sorted(node_ids, key=partial(_node_sort_key, graph)):
        node = graph.get_node(node_id)
        if node is None:
            continue
        for callsite in _ordered_node_callsites(node):
            result = callsite.result
            if result is None or not (
                result.direct_identifier or result.direct_field_path
            ):
                continue
            if shown_lines is not None and result.line not in shown_lines:
                continue
            results.append(
                (
                    TrackedObjectSubject(
                        node_id,
                        node.file_path,
                        result.start_byte,
                        result.end_byte,
                    ),
                    {
                        "kind": "call_result",
                        "function_id": node_id,
                        "line": result.line,
                        "start_byte": result.start_byte,
                        "end_byte": result.end_byte,
                        "expression": result.text,
                        "call_symbol": callsite.symbol,
                    },
                )
            )
    return tuple(results)


def _subject_model_data(subject: SecuritySubject) -> dict[str, object]:
    if isinstance(subject, ParameterSubject):
        return {
            "kind": "parameter",
            "function_id": subject.function_id,
            "index": subject.index,
        }
    if isinstance(subject, ReturnSubject):
        return {"kind": "return", "function_id": subject.function_id}
    return {
        "kind": "tracked_object",
        "function_id": subject.function_id,
        "file_path": subject.file_path,
        "start_byte": subject.start_byte,
        "end_byte": subject.end_byte,
    }


def _finding_evidence_key(
    node: FunctionNode,
    line: int,
    item: Mapping[str, Any],
) -> str:
    payload = {
        "file": node.file_path,
        "function": node.unique_name,
        "line": line,
        "issue": " ".join(str(item.get("issue") or "").lower().split()),
        "state": "local",
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
