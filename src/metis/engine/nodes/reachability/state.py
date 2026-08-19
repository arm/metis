# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Deterministic function contracts for Reachability review."""

from __future__ import annotations

from collections import defaultdict
from collections import deque
from collections.abc import Callable
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import replace
from typing import Literal

from metis.engine.codegraph import CallSite
from metis.engine.codegraph import CodeExpression
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import ControlCondition
from metis.engine.codegraph import FunctionNode

from .graph_utils import _node_sort_key

FactPredicate = Literal["null"]
FactOrigin = Literal["observed", "derived", "hypothesis"]
NormalExitStatus = Literal["unknown", "impossible"]
EffectOperation = Literal["negate"]


@dataclass(frozen=True, slots=True)
class ParameterSubject:
    function_id: str
    index: int

    def __post_init__(self) -> None:
        if not self.function_id or self.index < 0:
            raise ValueError(
                "Parameter subject requires a function and non-negative index"
            )


@dataclass(frozen=True, slots=True)
class ReturnSubject:
    function_id: str

    def __post_init__(self) -> None:
        if not self.function_id:
            raise ValueError("Return subject requires a function")


@dataclass(frozen=True, slots=True)
class TrackedObjectSubject:
    function_id: str
    file_path: str
    start_byte: int
    end_byte: int

    def __post_init__(self) -> None:
        if (
            not self.function_id
            or not self.file_path
            or self.start_byte < 0
            or self.end_byte <= self.start_byte
        ):
            raise ValueError("Tracked object requires a grounded non-empty source span")


SecuritySubject = ParameterSubject | ReturnSubject | TrackedObjectSubject


@dataclass(frozen=True, slots=True)
class FactAtom:
    subject: SecuritySubject
    predicate: FactPredicate


@dataclass(frozen=True, slots=True)
class FactLiteral:
    atom: FactAtom
    truth: Literal["asserted", "negated"]
    evidence_line: int
    origin: FactOrigin = "hypothesis"


@dataclass(frozen=True, slots=True)
class StateEffect:
    operation: EffectOperation
    atom: FactAtom
    origin: FactOrigin
    evidence_line: int


@dataclass(frozen=True, slots=True)
class GuardedTransfer:
    requirements: tuple[FactLiteral, ...] = ()
    effects: tuple[StateEffect, ...] = ()


@dataclass(frozen=True, slots=True)
class NormalExit:
    status: NormalExitStatus = "unknown"
    origin: Literal["observed", "derived"] | None = None
    evidence_line: int | None = None

    def __post_init__(self) -> None:
        if self.status == "unknown":
            if self.origin is not None or self.evidence_line is not None:
                raise ValueError("Unknown normal-exit evidence has no provenance")
            return
        if self.origin is None or self.evidence_line is None or self.evidence_line < 1:
            raise ValueError("Known normal-exit evidence requires provenance")


@dataclass(frozen=True, slots=True)
class FunctionContract:
    function_id: str
    normal_return_transfers: tuple[GuardedTransfer, ...] = ()
    normal_exit: NormalExit = NormalExit()


def augment_function_contracts(
    graph: CodeGraph,
    *,
    progress_callback: Callable[[int, int], None] | None = None,
) -> dict[str, FunctionContract]:
    """Derive source-proven normal-return facts to a fixed point."""

    augmented = {
        node_id: FunctionContract(
            node_id,
            normal_exit=(
                NormalExit("impossible", "observed", node.line_number)
                if node.has_tag("control.noreturn")
                else NormalExit()
            ),
        )
        for node_id, node in graph.nodes.items()
    }
    callers: dict[str, set[str]] = defaultdict(set)
    for node in graph.nodes.values():
        for target_id in node.resolved_calls:
            if target_id in graph.nodes:
                callers[target_id].add(node.unique_name)
    pending = deque(sorted(graph.nodes, key=lambda value: _node_sort_key(graph, value)))
    scheduled = set(pending)
    processed = 0
    if progress_callback is not None:
        progress_callback(0, len(pending))
    while pending:
        function_id = pending.popleft()
        scheduled.discard(function_id)
        processed += 1
        node = graph.nodes[function_id]
        transfer = _derive_nonnull_return_transfer(node, augmented)
        contract = augmented[function_id]
        if transfer is None or transfer in contract.normal_return_transfers:
            if progress_callback is not None:
                progress_callback(processed, processed + len(pending))
            continue
        augmented[function_id] = replace(
            contract,
            normal_return_transfers=tuple(
                sorted((*contract.normal_return_transfers, transfer), key=repr)
            ),
        )
        for caller_id in sorted(
            callers.get(function_id, ()),
            key=lambda value: _node_sort_key(graph, value),
        ):
            if caller_id not in scheduled:
                pending.append(caller_id)
                scheduled.add(caller_id)
        if progress_callback is not None:
            progress_callback(processed, processed + len(pending))
    return augmented


def _callsite_must_null_literals(
    owner: FunctionNode,
    callsite: CallSite,
    target_id: str,
) -> tuple[FactLiteral, ...]:
    owner_parameters = {
        parameter.name for parameter in owner.parameters if parameter.name
    }
    literals: set[FactLiteral] = set()
    for condition in callsite.must_conditions:
        null_condition = condition.null_condition
        if null_condition is None:
            continue
        selected = (
            null_condition.when_true if condition.truth else null_condition.when_false
        )
        for fact in selected:
            name = fact.value.direct_identifier
            if not name or name not in owner_parameters:
                continue
            for argument_index, argument in enumerate(callsite.arguments):
                if argument.direct_identifier != name:
                    continue
                literals.add(
                    FactLiteral(
                        FactAtom(
                            ParameterSubject(target_id, argument_index),
                            "null",
                        ),
                        "asserted" if fact.is_null else "negated",
                        condition.expression.line,
                        "derived",
                    )
                )
    return tuple(sorted(literals, key=repr))


def _derive_nonnull_return_transfer(
    node: FunctionNode,
    contracts: Mapping[str, FunctionContract],
) -> GuardedTransfer | None:
    if node.language != "c" or not node.returns:
        return None
    final_return = node.returns[-1]
    if final_return.value is None or final_return.conditions:
        return None
    requirements: list[FactLiteral] = []
    for early_return in node.returns[:-1]:
        if not early_return.returns_null:
            return None
        excluded = _return_exclusion_requirements(node, early_return.conditions)
        if not excluded:
            return None
        requirements.extend(excluded)

    forwarded = _forwarded_return_requirements(
        node,
        final_return.value,
        contracts,
    )
    if forwarded is None:
        return None
    requirements.extend(forwarded)
    return GuardedTransfer(
        requirements=tuple(sorted(set(requirements), key=repr)),
        effects=(
            StateEffect(
                "negate",
                FactAtom(ReturnSubject(node.unique_name), "null"),
                "derived",
                final_return.line,
            ),
        ),
    )


def _return_exclusion_requirements(
    node: FunctionNode,
    conditions: tuple[ControlCondition, ...],
) -> tuple[FactLiteral, ...]:
    parameter_indexes = {
        parameter.name: index
        for index, parameter in enumerate(node.parameters)
        if parameter.name
    }
    for condition in conditions:
        null_condition = condition.null_condition
        if null_condition is None:
            continue
        opposite = (
            null_condition.when_false if condition.truth else null_condition.when_true
        )
        requirements: list[FactLiteral] = []
        for fact in opposite:
            parameter_index = parameter_indexes.get(fact.value.direct_identifier)
            if parameter_index is None:
                requirements = []
                break
            requirements.append(
                FactLiteral(
                    FactAtom(
                        ParameterSubject(node.unique_name, parameter_index), "null"
                    ),
                    "asserted" if fact.is_null else "negated",
                    condition.expression.line,
                    "derived",
                )
            )
        if requirements:
            return tuple(requirements)
    return ()


def _forwarded_return_requirements(
    node: FunctionNode,
    return_value: CodeExpression,
    contracts: Mapping[str, FunctionContract],
) -> tuple[FactLiteral, ...] | None:
    direct_call = next(
        (
            callsite
            for callsite in node.call_sites
            if callsite.start_byte == return_value.start_byte
            and callsite.end_byte == return_value.end_byte
        ),
        None,
    )
    if direct_call is not None:
        return _callee_nonnull_requirements(node, direct_call, contracts)
    local_name = return_value.direct_identifier
    if not local_name or node.language != "c":
        return None
    assignments = [
        callsite
        for callsite in node.call_sites
        if callsite.result is not None
        and callsite.result.direct_identifier == local_name
        and callsite.end_byte < return_value.start_byte
    ]
    if len(assignments) != 1:
        return None
    assignment_call = assignments[0]
    if assignment_call.conditions:
        return None
    if any(
        local_name in argument.identifiers and argument.direct_identifier != local_name
        for callsite in node.call_sites
        for argument in callsite.arguments
    ):
        return None
    if expression_modified_between(
        node,
        return_value,
        start_byte=assignment_call.end_byte,
        end_byte=return_value.start_byte,
    ):
        return None
    if _fatal_null_branch_proves_nonnull(
        node,
        local_name,
        assignment_call,
        return_value.start_byte,
        contracts,
    ):
        return ()
    return _callee_nonnull_requirements(node, assignment_call, contracts)


def expression_modified_between(
    node: FunctionNode,
    expression: CodeExpression,
    *,
    start_byte: int,
    end_byte: int,
) -> bool:
    """Return whether source syntax can replace an expression's tracked value."""

    direct_identifier = expression.direct_identifier
    direct_field_path = expression.direct_field_path
    field_root = direct_field_path.partition(".")[0]
    identifiers = frozenset(expression.identifiers)
    for assignment in node.assignments:
        if not start_byte < assignment.start_byte < end_byte:
            continue
        target = assignment.target
        if not target.direct_identifier and not target.direct_field_path:
            return True
        if direct_identifier and target.direct_identifier == direct_identifier:
            return True
        if field_root and target.direct_identifier == field_root:
            return True
        target_path = target.direct_field_path
        if (
            direct_field_path
            and target_path
            and (
                direct_field_path == target_path
                or direct_field_path.startswith(f"{target_path}.")
            )
        ):
            return True
    return any(
        start_byte < loop.start_byte < end_byte
        and bool(
            identifiers.intersection(
                (*loop.written_identifiers, *loop.addressed_identifiers)
            )
        )
        for loop in node.loops
    )


def _fatal_null_branch_proves_nonnull(
    node: FunctionNode,
    local_name: str,
    assignment_call: CallSite,
    return_start_byte: int,
    contracts: Mapping[str, FunctionContract],
) -> bool:
    intervening_calls = [
        callsite
        for callsite in node.call_sites
        if assignment_call.end_byte < callsite.start_byte < return_start_byte
    ]
    if len(intervening_calls) != 1:
        return False
    callsite = intervening_calls[0]
    if len(callsite.conditions) != 1 or len(callsite.target_ids) != 1:
        return False
    target_contract = contracts.get(callsite.target_ids[0])
    if target_contract is None or target_contract.normal_exit.status != "impossible":
        return False
    condition = callsite.conditions[0]
    null_condition = condition.null_condition
    if null_condition is None:
        return False
    selected = (
        null_condition.when_true if condition.truth else null_condition.when_false
    )
    opposite = (
        null_condition.when_false if condition.truth else null_condition.when_true
    )
    return bool(
        len(selected) == 1
        and len(opposite) == 1
        and selected[0].value.direct_identifier == local_name
        and selected[0].is_null
        and opposite[0].value.direct_identifier == local_name
        and not opposite[0].is_null
    )


def _callee_nonnull_requirements(
    owner: FunctionNode,
    callsite: CallSite,
    contracts: Mapping[str, FunctionContract],
) -> tuple[FactLiteral, ...] | None:
    if len(callsite.target_ids) != 1:
        return None
    target_id = callsite.target_ids[0]
    owner_parameters = {
        parameter.name: index
        for index, parameter in enumerate(owner.parameters)
        if parameter.name
    }
    for transfer in _callee_nonnull_transfers(callsite, contracts):
        mapped: list[FactLiteral] = []
        for requirement in transfer.requirements:
            if not (
                isinstance(requirement.atom.subject, ParameterSubject)
                and requirement.atom.subject.function_id == target_id
            ):
                mapped = []
                break
            parameter_index = requirement.atom.subject.index
            if parameter_index >= len(callsite.arguments):
                mapped = []
                break
            owner_index = owner_parameters.get(
                callsite.arguments[parameter_index].direct_identifier
            )
            if owner_index is None:
                mapped = []
                break
            mapped.append(
                FactLiteral(
                    FactAtom(
                        ParameterSubject(owner.unique_name, owner_index),
                        requirement.atom.predicate,
                    ),
                    requirement.truth,
                    callsite.line,
                    "derived",
                )
            )
        if len(mapped) == len(transfer.requirements):
            return tuple(mapped)
    return None


def callsite_has_deterministic_nonnull_return(
    owner: FunctionNode,
    callsite: CallSite,
    contracts: Mapping[str, FunctionContract],
) -> bool:
    """Return whether source-derived callsite facts prove a non-null result."""

    if len(callsite.target_ids) != 1:
        return False
    target_id = callsite.target_ids[0]
    proven = {
        (requirement.atom, requirement.truth)
        for requirement in _callsite_must_null_literals(owner, callsite, target_id)
    }
    return any(
        all(
            (requirement.atom, requirement.truth) in proven
            for requirement in transfer.requirements
        )
        for transfer in _callee_nonnull_transfers(callsite, contracts)
    )


def _callee_nonnull_transfers(
    callsite: CallSite,
    contracts: Mapping[str, FunctionContract],
) -> tuple[GuardedTransfer, ...]:
    if len(callsite.target_ids) != 1:
        return ()
    target_id = callsite.target_ids[0]
    contract = contracts.get(target_id)
    if contract is None:
        return ()
    return tuple(
        transfer
        for transfer in contract.normal_return_transfers
        if all(
            requirement.origin in {"observed", "derived"}
            for requirement in transfer.requirements
        )
        and any(
            effect.atom == FactAtom(ReturnSubject(target_id), "null")
            and effect.operation == "negate"
            and effect.origin in {"observed", "derived"}
            for effect in transfer.effects
        )
    )
