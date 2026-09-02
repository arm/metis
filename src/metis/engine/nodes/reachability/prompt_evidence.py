# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Pure prompt-evidence serialization for incremental Reachability review."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
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
from metis.utils import source_lines

from .graph_utils import _node_sort_key
from .source_context import _source_map
from .state import FunctionContract
from .state import GuardedTransfer
from .state import ParameterSubject
from .state import ReturnSubject
from .state import SecuritySubject
from .state import TrackedObjectSubject

_NUMBERED_LINE = re.compile(r"^[ \t]*(\d+):[^\S\n]*\S", re.MULTILINE)
_EXPRESSION_MARKERS = frozenset(
    {"text", "span", "ids", "fields", "direct_id", "direct_field", "cols"}
)
_EXPRESSION_FIELDS = _EXPRESSION_MARKERS | {"line", "result_index"}
_ATOM_LIST_FIELDS = frozenset(
    {"ids", "fields", "writes", "addresses", "condition_writes"}
)
_ATOM_VALUE_FIELDS = frozenset({"direct_id", "direct_field"})


@dataclass(frozen=True, slots=True)
class _PromptReferences:
    function_indexes: Mapping[str, int]
    call_symbol_indexes: Mapping[str, int]
    condition_indexes: Mapping[tuple[str, ControlCondition], int]
    result_indexes: Mapping[tuple[str, int], int]


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
        _compact_repeated_evidence(_sparse_prompt_data(value)),
        sort_keys=True,
        separators=(",", ":"),
    )


def _shown_lines(source_text: str) -> frozenset[int]:
    return frozenset(int(match) for match in _NUMBERED_LINE.findall(source_text))


def _expression_key(
    value: object,
    *,
    inherited_line: int | None,
) -> str | None:
    if not isinstance(value, Mapping) or not value:
        return None
    fields = frozenset(value)
    if not fields <= _EXPRESSION_FIELDS or not fields & _EXPRESSION_MARKERS:
        return None
    prompt_value = value
    if "cols" in value and not isinstance(value.get("line"), int):
        if inherited_line is None:
            return None
        prompt_value = {**value, "line": inherited_line}
    return json.dumps(prompt_value, sort_keys=True, separators=(",", ":"))


def _compact_repeated_evidence(value: object) -> object:
    expression_counts: Counter[str] = Counter()

    def collect_expressions(
        item: object,
        *,
        inherited_line: int | None,
    ) -> None:
        expression_key = _expression_key(item, inherited_line=inherited_line)
        if expression_key is not None:
            expression_counts[expression_key] += 1
            return
        if isinstance(item, Mapping):
            explicit_line = item.get("line")
            mapped_line = (
                explicit_line if isinstance(explicit_line, int) else inherited_line
            )
            for child in item.values():
                collect_expressions(child, inherited_line=mapped_line)
        elif isinstance(item, (list, tuple)):
            for child in item:
                collect_expressions(child, inherited_line=inherited_line)

    collect_expressions(value, inherited_line=None)
    expression_rows = sorted(
        key for key, count in expression_counts.items() if count >= 2
    )
    expression_indexes = {
        expression: index for index, expression in enumerate(expression_rows)
    }

    def replace_expressions(
        item: object,
        *,
        inherited_line: int | None,
    ) -> object:
        expression_key = _expression_key(item, inherited_line=inherited_line)
        if expression_key in expression_indexes:
            return expression_indexes[expression_key]
        if isinstance(item, Mapping):
            explicit_line = item.get("line")
            mapped_line = (
                explicit_line if isinstance(explicit_line, int) else inherited_line
            )
            return {
                key: replace_expressions(child, inherited_line=mapped_line)
                for key, child in item.items()
            }
        if isinstance(item, (list, tuple)):
            return [
                replace_expressions(child, inherited_line=inherited_line)
                for child in item
            ]
        return item

    compact = replace_expressions(value, inherited_line=None)
    if not isinstance(compact, Mapping):
        return compact
    compact = dict(compact)
    if expression_rows:
        compact["expression_table"] = [
            json.loads(expression) for expression in expression_rows
        ]

    atom_counts: Counter[str] = Counter()

    def collect_atoms(item: object) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if key in _ATOM_VALUE_FIELDS and isinstance(child, str):
                    atom_counts[child] += 1
                elif key in _ATOM_LIST_FIELDS and isinstance(child, (list, tuple)):
                    atom_counts.update(
                        value for value in child if isinstance(value, str)
                    )
                else:
                    collect_atoms(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                collect_atoms(child)

    collect_atoms(compact)
    atom_rows = sorted(atom for atom, count in atom_counts.items() if count >= 2)
    atom_indexes = {atom: index for index, atom in enumerate(atom_rows)}

    def replace_atoms(item: object) -> object:
        if isinstance(item, Mapping):
            result: dict[object, object] = {}
            for key, child in item.items():
                if key in _ATOM_VALUE_FIELDS and isinstance(child, str):
                    result[key] = atom_indexes.get(child, child)
                elif key in _ATOM_LIST_FIELDS and isinstance(child, (list, tuple)):
                    result[key] = [
                        atom_indexes.get(value, value)
                        if isinstance(value, str)
                        else value
                        for value in child
                    ]
                else:
                    result[key] = replace_atoms(child)
            return result
        if isinstance(item, (list, tuple)):
            return [replace_atoms(child) for child in item]
        return item

    compact = replace_atoms(compact)
    if isinstance(compact, dict) and atom_rows:
        compact["atom_table"] = atom_rows
    return compact


def _source_span_replacement(
    value: Mapping[object, object],
    *,
    source_map: SourceMap,
    complete_lines: frozenset[int],
    evidence_line: int | None,
) -> tuple[frozenset[str], tuple[int, int] | None]:
    span = value.get("span")
    if not isinstance(span, (list, tuple)) or len(span) != 2:
        return frozenset(), None
    start_byte, end_byte = span
    if not isinstance(start_byte, int) or not isinstance(end_byte, int):
        return frozenset(), None
    if start_byte < 0 or end_byte <= start_byte:
        return frozenset(), None
    start_line = source_map.byte_to_line(start_byte)
    end_line = source_map.byte_to_line(end_byte - 1)
    if (
        start_line != end_line
        or evidence_line != start_line
        or start_line not in complete_lines
    ):
        return frozenset(), None
    source_text = source_map.byte_slice(start_byte, end_byte)
    omitted_fields = frozenset(
        field for field in ("text", "expression") if value.get(field) == source_text
    )
    if not omitted_fields:
        return frozenset(), None
    line_start_byte = source_map.line_to_byte(start_line)
    start_column = len(source_map.byte_slice(line_start_byte, start_byte))
    columns = (start_column, start_column + len(source_text))
    removed_size = (
        len(json.dumps({"span": span}, separators=(",", ":")))
        - 2
        + sum(
            len(json.dumps({field: source_text}, separators=(",", ":"))) - 2
            for field in omitted_fields
        )
    )
    replacement_size = len(json.dumps({"cols": columns}, separators=(",", ":"))) - 2
    if replacement_size >= removed_size:
        return frozenset(), None
    return omitted_fields, columns


def _source_span_prompt_data(
    value: object,
    *,
    source_map: SourceMap,
    file_path: str,
    complete_lines: frozenset[int],
    owning_file_path: str,
    owning_line: int | None,
) -> object:
    if isinstance(value, Mapping):
        explicit_file_path = value.get("file_path")
        mapped_file_path = (
            explicit_file_path
            if isinstance(explicit_file_path, str)
            else owning_file_path
        )
        explicit_line = value.get("line")
        mapped_line = explicit_line if isinstance(explicit_line, int) else owning_line
        result = {
            key: _source_span_prompt_data(
                item,
                source_map=source_map,
                file_path=file_path,
                complete_lines=complete_lines,
                owning_file_path=mapped_file_path,
                owning_line=mapped_line,
            )
            for key, item in value.items()
        }
        if mapped_file_path != file_path:
            return result
        omitted_fields, source_columns = _source_span_replacement(
            value,
            source_map=source_map,
            complete_lines=complete_lines,
            evidence_line=mapped_line,
        )
        if source_columns is None:
            return result
        return {
            **{
                key: item
                for key, item in result.items()
                if key not in omitted_fields | {"span"}
            },
            "cols": list(source_columns),
        }
    if isinstance(value, (list, tuple)):
        return [
            _source_span_prompt_data(
                item,
                source_map=source_map,
                file_path=file_path,
                complete_lines=complete_lines,
                owning_file_path=owning_file_path,
                owning_line=owning_line,
            )
            for item in value
        ]
    return value


def _compact_source_evidence(
    value: object,
    *,
    codebase_path: str,
    file_path: str,
    source_text: str,
    source_for_path: Callable[[str], bytes | None] | None = None,
) -> object:
    source_map = _source_map(codebase_path, file_path, source_for_path)
    if source_map is None:
        return value
    complete_line_numbers: set[int] = set()
    for rendered_line in source_lines(source_text):
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
        value,
        source_map=source_map,
        file_path=file_path,
        complete_lines=complete_lines,
        owning_file_path=file_path,
        owning_line=None,
    )


def _function_ref(references: _PromptReferences, function_id: str) -> int | str:
    return references.function_indexes.get(function_id, function_id)


def _expression_data(
    expression: CodeExpression,
    *,
    inherited_line: int | None = None,
) -> dict[str, object]:
    return {
        "text": expression.text,
        "line": expression.line if expression.line != inherited_line else None,
        "span": [expression.start_byte, expression.end_byte],
        "ids": list(expression.identifiers),
        "fields": list(expression.field_paths),
        "direct_id": expression.direct_identifier,
        "direct_field": expression.direct_field_path,
    }


def _condition_data(condition: ControlCondition) -> dict[str, object]:
    return {
        "line": condition.expression.line,
        "expression": _expression_data(
            condition.expression,
            inherited_line=condition.expression.line,
        ),
        "truth": condition.truth,
        "null_condition": (
            {
                "when_true": [
                    _null_fact_data(fact, inherited_line=condition.expression.line)
                    for fact in condition.null_condition.when_true
                ],
                "when_false": [
                    _null_fact_data(fact, inherited_line=condition.expression.line)
                    for fact in condition.null_condition.when_false
                ],
            }
            if condition.null_condition is not None
            else None
        ),
    }


def _null_fact_data(
    fact: NullFact,
    *,
    inherited_line: int,
) -> dict[str, object]:
    return {
        "value": _expression_data(fact.value, inherited_line=inherited_line),
        "is_null": fact.is_null,
    }


def _condition_refs(
    conditions: Sequence[ControlCondition],
    *,
    file_path: str,
    references: _PromptReferences,
) -> list[int]:
    return [references.condition_indexes[(file_path, item)] for item in conditions]


def _assignment_data(
    assignment: ValueAssignment,
    *,
    file_path: str,
    references: _PromptReferences,
) -> dict[str, object]:
    return {
        "target": _expression_data(
            assignment.target,
            inherited_line=assignment.line,
        ),
        "value": _expression_data(
            assignment.value,
            inherited_line=assignment.line,
        ),
        "operator": assignment.operator,
        "line": assignment.line,
        "span": [assignment.start_byte, assignment.end_byte],
        "conditions": _condition_refs(
            assignment.conditions,
            file_path=file_path,
            references=references,
        ),
    }


def _loop_data(loop: LoopStructure) -> dict[str, object]:
    return {
        "condition": (
            _expression_data(loop.condition, inherited_line=loop.line)
            if loop.condition is not None
            else None
        ),
        "line": loop.line,
        "span": [loop.start_byte, loop.end_byte],
        "writes": list(loop.written_identifiers),
        "addresses": list(loop.addressed_identifiers),
        "condition_writes": sorted(
            set(loop.condition.identifiers if loop.condition is not None else ())
            & set(loop.written_identifiers)
        ),
    }


def _return_data(
    return_site: ReturnSite,
    *,
    file_path: str,
    references: _PromptReferences,
) -> dict[str, object]:
    return {
        "value": (
            _expression_data(return_site.value, inherited_line=return_site.line)
            if return_site.value is not None
            else None
        ),
        "line": return_site.line,
        "span": [return_site.start_byte, return_site.end_byte],
        "conditions": _condition_refs(
            return_site.conditions,
            file_path=file_path,
            references=references,
        ),
        "returns_null": return_site.returns_null,
    }


def _call_expression_data(
    call: CallSite,
    *,
    node: FunctionNode,
    call_index: int,
    references: _PromptReferences,
) -> dict[str, object]:
    result = (
        _expression_data(call.result, inherited_line=call.line)
        if call.result is not None
        else None
    )
    result_index = references.result_indexes.get((node.unique_name, call_index))
    if result is not None and result_index is not None:
        result["result_index"] = result_index
    return {
        "arguments": [
            _expression_data(item, inherited_line=call.line) for item in call.arguments
        ],
        "conditions": _condition_refs(
            call.conditions,
            file_path=node.file_path,
            references=references,
        ),
        "must_conditions": _condition_refs(
            call.must_conditions,
            file_path=node.file_path,
            references=references,
        ),
        "result": result,
    }


def _tag_data(
    node: FunctionNode,
    *,
    include_syntax_tags: bool = False,
) -> dict[str, list[str]]:
    return {
        name: [tag.value, tag.reason]
        for name, tag in sorted(node.tags.items())
        if include_syntax_tags or not name.startswith("syntax.")
    }


def _boundary_call_data(
    node: FunctionNode,
    call: CallSite,
    call_index: int,
    *,
    include_call_index: bool,
    references: _PromptReferences,
) -> dict[str, object]:
    return {
        "call_index": call_index if include_call_index else None,
        "line": call.line,
        "span": [call.start_byte, call.end_byte],
        "symbol": references.call_symbol_indexes[call.symbol],
        "kind": call.kind if call.kind != "direct" else None,
        "argument_count": (
            call.argument_count if call.argument_count != len(call.arguments) else None
        ),
        "target_ids": [
            _function_ref(references, target_id) for target_id in call.target_ids
        ],
        "complete": True if call.targets_complete else None,
        **_call_expression_data(
            call,
            node=node,
            call_index=call_index,
            references=references,
        ),
    }


def _codegraph_evidence_data(
    graph: CodeGraph,
    nodes: Sequence[FunctionNode],
    contracts: Mapping[str, FunctionContract] | None = None,
    *,
    shown_lines: frozenset[int] | None = None,
    file_path: str,
) -> dict[str, object]:
    contract_map = contracts or {}
    ordered_nodes = tuple(
        sorted(
            (graph.nodes.get(node.unique_name, node) for node in nodes),
            key=partial(_node_sort_key, graph),
        )
    )
    current_ids = {node.unique_name for node in ordered_nodes}
    direct_edges = {
        (node.unique_name, target_id)
        for node in ordered_nodes
        for target_id in node.resolved_calls
        if target_id in graph.nodes
    }
    represented_edges = {
        (node.unique_name, target_id)
        for node in ordered_nodes
        for call in _ordered_node_callsites(node)
        for target_id in call.target_ids
    }
    direct_target_ids = {
        target_id
        for _caller_id, target_id in direct_edges | represented_edges
        if target_id in graph.nodes
    }
    direct_nodes = tuple(
        graph.nodes[node_id]
        for node_id in sorted(
            direct_target_ids,
            key=partial(_node_sort_key, graph),
        )
        if node_id not in current_ids
    )
    all_nodes = (*ordered_nodes, *direct_nodes)
    referenced_node_ids = {
        target_id
        for node in all_nodes
        for call in _ordered_node_callsites(node)
        for target_id in call.target_ids
        if target_id in graph.nodes
    }
    referenced_only_ids = sorted(
        referenced_node_ids - current_ids - direct_target_ids,
        key=partial(_node_sort_key, graph),
    )
    function_ids = [node.unique_name for node in all_nodes] + referenced_only_ids
    call_symbols = sorted(
        {call.symbol for node in all_nodes for call in _ordered_node_callsites(node)}
    )
    condition_keys: list[tuple[str, ControlCondition]] = []
    for node in ordered_nodes:
        for assignment in node.assignments:
            condition_keys.extend(
                (node.file_path, condition) for condition in assignment.conditions
            )
        for return_site in node.returns:
            condition_keys.extend(
                (node.file_path, condition) for condition in return_site.conditions
            )
    for node in all_nodes:
        for call in _ordered_node_callsites(node):
            condition_keys.extend(
                (node.file_path, condition)
                for condition in (*call.conditions, *call.must_conditions)
            )
    ordered_conditions = tuple(dict.fromkeys(condition_keys))
    call_results = _call_result_entries(
        graph,
        tuple(node.unique_name for node in ordered_nodes),
        shown_lines=shown_lines,
    )
    references = _PromptReferences(
        function_indexes={
            function_id: function_index
            for function_index, function_id in enumerate(function_ids)
        },
        call_symbol_indexes={
            symbol: symbol_index for symbol_index, symbol in enumerate(call_symbols)
        },
        condition_indexes={
            condition: condition_index
            for condition_index, condition in enumerate(ordered_conditions)
        },
        result_indexes={
            call_key: result_index
            for result_index, (_subject, call_key) in enumerate(call_results)
        },
    )
    residual_edges = sorted(direct_edges - represented_edges)
    direct_contract_ids = tuple(
        sorted(direct_target_ids, key=partial(_node_sort_key, graph))
    )
    return {
        "function_ids": [
            (
                function_id[len(file_path) :]
                if function_id.startswith(f"{file_path}::")
                else function_id
            )
            for function_id in function_ids
        ],
        "call_symbols": call_symbols,
        "function_tags": {
            str(references.function_indexes[node_id]): tags
            for node_id in referenced_only_ids
            if (tags := _tag_data(graph.nodes[node_id], include_syntax_tags=True))
        },
        "condition_table": [
            {
                "file_path": condition_file if condition_file != file_path else None,
                **_condition_data(condition),
            }
            for condition_file, condition in ordered_conditions
        ],
        "functions": [
            _discovery_function_data(
                node,
                file_path=file_path,
                references=references,
            )
            for node in ordered_nodes
        ],
        "direct_edges": [
            [
                _function_ref(references, caller_id),
                _function_ref(references, target_id),
            ]
            for caller_id, target_id in residual_edges
        ],
        "direct_functions": [
            {
                **_function_boundary_data(
                    node,
                    file_path=file_path,
                    references=references,
                    include_syntax_tags=True,
                ),
                "entrypoint": True if node.is_public_entrypoint else None,
            }
            for node in direct_nodes
        ],
        "direct_function_contracts": [
            {
                "file_path": (
                    graph.nodes[node_id].file_path
                    if graph.nodes[node_id].file_path != file_path
                    else None
                ),
                **_direct_contract_data(
                    contract_map[node_id],
                    references=references,
                ),
            }
            for node_id in direct_contract_ids
            if node_id in contract_map
        ],
    }


def _direct_contract_data(
    contract: FunctionContract,
    *,
    references: _PromptReferences,
) -> dict[str, object]:
    return {
        "function": _function_ref(references, contract.function_id),
        "normal_returns": [
            _guarded_transfer_data(transfer, references=references)
            for transfer in contract.normal_return_transfers
        ],
        "normal_exit": {
            "status": contract.normal_exit.status,
            "origin": contract.normal_exit.origin,
            "line": contract.normal_exit.evidence_line,
        },
    }


def _guarded_transfer_data(
    transfer: GuardedTransfer,
    *,
    references: _PromptReferences,
) -> dict[str, object]:
    return {
        "requirements": [
            {
                "atom": {
                    "subject": _subject_model_data(
                        item.atom.subject,
                        references=references,
                    ),
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
                    "subject": _subject_model_data(
                        item.atom.subject,
                        references=references,
                    ),
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
    node: FunctionNode,
    *,
    file_path: str,
    include_call_indexes: bool = False,
    references: _PromptReferences,
    include_syntax_tags: bool = False,
) -> dict[str, object]:
    return {
        "function_id": _function_ref(references, node.unique_name),
        "file_path": node.file_path if node.file_path != file_path else None,
        "lines": [node.line_number, node.end_line or node.line_number],
        "parameter_count": node.parameter_count,
        "parameters": [
            [parameter.name, parameter.type_spelling] for parameter in node.parameters
        ],
        "tags": _tag_data(node, include_syntax_tags=include_syntax_tags),
        "calls": [
            _boundary_call_data(
                node,
                call,
                call_index,
                include_call_index=include_call_indexes,
                references=references,
            )
            for call_index, call in enumerate(_ordered_node_callsites(node))
        ],
    }


def _discovery_function_data(
    node: FunctionNode,
    *,
    file_path: str,
    references: _PromptReferences,
) -> dict[str, object]:
    return {
        **_function_boundary_data(
            node,
            file_path=file_path,
            include_call_indexes=True,
            references=references,
            include_syntax_tags=True,
        ),
        "entrypoint": True if node.is_public_entrypoint else None,
        "assignments": [
            _assignment_data(
                item,
                file_path=node.file_path,
                references=references,
            )
            for item in node.assignments
        ],
        "loops": [_loop_data(item) for item in node.loops],
        "returns": [
            _return_data(
                item,
                file_path=node.file_path,
                references=references,
            )
            for item in node.returns
        ],
    }


def _call_result_entries(
    graph: CodeGraph,
    node_ids: Sequence[str],
    *,
    shown_lines: frozenset[int] | None,
) -> tuple[tuple[TrackedObjectSubject, tuple[str, int]], ...]:
    results: list[tuple[TrackedObjectSubject, tuple[str, int]]] = []
    for node_id in sorted(node_ids, key=partial(_node_sort_key, graph)):
        node = graph.get_node(node_id)
        if node is None:
            continue
        for call_index, callsite in enumerate(_ordered_node_callsites(node)):
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
                    (node_id, call_index),
                )
            )
    return tuple(results)


def _subject_model_data(
    subject: SecuritySubject,
    *,
    references: _PromptReferences,
) -> dict[str, object]:
    if isinstance(subject, ParameterSubject):
        return {
            "kind": "parameter",
            "function_id": _function_ref(references, subject.function_id),
            "index": subject.index,
        }
    if isinstance(subject, ReturnSubject):
        return {
            "kind": "return",
            "function_id": _function_ref(references, subject.function_id),
        }
    return {
        "kind": "tracked_object",
        "function_id": _function_ref(references, subject.function_id),
        "file_path": subject.file_path,
        "span": [subject.start_byte, subject.end_byte],
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
