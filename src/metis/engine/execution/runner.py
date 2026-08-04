# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import replace
from time import perf_counter
from typing import Any
from typing import get_origin

from pydantic import TypeAdapter
from pydantic import ValidationError

from .compiler import StagePlan
from .compiler import _PlannedNode
from .contracts import ExecutionDiagnostic
from .contracts import ExecutionStatus
from .contracts import NodeContext
from .contracts import NodeInvocation
from .contracts import NodeRegistration
from .contracts import StageName
from .contracts import annotation_allows_none


@dataclass(frozen=True, slots=True)
class StageRun:
    status: ExecutionStatus
    outputs: Mapping[str, object]
    diagnostics: tuple[ExecutionDiagnostic, ...] = ()


def run_stage(
    stage_name: StageName,
    planned: StagePlan,
    context: NodeContext,
    initial_inputs: Mapping[str, object],
) -> StageRun:
    outputs: dict[str, Mapping[str, object]] = {}
    diagnostics: list[ExecutionDiagnostic] = []
    status = ExecutionStatus.OK
    failed: set[str] = set()
    stage_started = perf_counter()
    _progress(context, {"event": "execution_stage_start", "stage": stage_name})
    for node in planned.nodes:
        if node.required_dependencies & failed:
            failed.add(node.name)
            _progress(
                context,
                {
                    "event": "execution_node_skipped",
                    "stage": stage_name,
                    "node": node.name,
                    "reason": "dependency_failed",
                },
            )
            continue
        _progress(
            context,
            {
                "event": "execution_node_start",
                "stage": stage_name,
                "node": node.name,
            },
        )
        node_started = perf_counter()
        node_status = ExecutionStatus.ERROR
        try:
            inputs = _resolve_inputs(node, outputs, initial_inputs)
            node_context = replace(
                context,
                capabilities=node.capabilities,
            )
            result = node.registration.execute(
                NodeInvocation(
                    configuration=node.configuration,
                    inputs=inputs,
                    context=node_context,
                    formats=node.definition.formats,
                    filename=node.definition.filename,
                )
            )
            diagnostics.extend(result.diagnostics)
            node_status = result.status
            if result.status is ExecutionStatus.ERROR:
                failed.add(node.name)
                status = ExecutionStatus.ERROR
            else:
                outputs[node.name] = _validate_outputs(
                    node.registration,
                    result.outputs,
                )
                if (
                    result.status is ExecutionStatus.INCONCLUSIVE
                    and status is ExecutionStatus.OK
                ):
                    status = ExecutionStatus.INCONCLUSIVE
        except Exception as exc:
            node_status = ExecutionStatus.ERROR
            diagnostics.append(
                ExecutionDiagnostic(
                    code="execution.node_failed",
                    message=f"Execution node {stage_name}.{node.name} failed: {exc}",
                )
            )
            failed.add(node.name)
            status = ExecutionStatus.ERROR
        _progress(
            context,
            {
                "event": "execution_node_end",
                "stage": stage_name,
                "node": node.name,
                "status": node_status.value,
                "duration_seconds": perf_counter() - node_started,
            },
        )
    if not planned.output_bindings:
        stage_outputs: dict[str, object] = {
            name: _single_or_mapping(values) for name, values in outputs.items()
        }
    else:
        stage_outputs = {
            name: _resolve_source(source, outputs, {})
            for name, source in planned.output_bindings.items()
            if _source_is_available(source, outputs)
        }
    _progress(
        context,
        {
            "event": "execution_stage_end",
            "stage": stage_name,
            "status": status.value,
            "duration_seconds": perf_counter() - stage_started,
        },
    )
    return StageRun(status, stage_outputs, tuple(diagnostics))


def _progress(context: NodeContext, event: Mapping[str, object]) -> None:
    if context.callbacks.progress is not None:
        context.callbacks.progress(event)


def _resolve_inputs(
    node: _PlannedNode,
    outputs: Mapping[str, Mapping[str, object]],
    initial_inputs: Mapping[str, object],
) -> dict[str, object]:
    resolved: dict[str, object] = {}
    for input_name, annotation in node.registration.inputs.items():
        source = node.input_bindings.get(input_name)
        if source is None:
            value = initial_inputs.get(input_name)
        elif isinstance(source, tuple):
            value = tuple(
                _resolve_source(item, outputs, initial_inputs) for item in source
            )
        elif source.startswith("$inputs."):
            value = initial_inputs[source.removeprefix("$inputs.")]
        elif not _source_is_available(source, outputs) and annotation_allows_none(
            annotation
        ):
            value = None
        else:
            value = _resolve_source(source, outputs, initial_inputs)
        resolved[input_name] = _validate_value(annotation, value)
    return resolved


def _validate_outputs(
    registration: NodeRegistration,
    outputs: Mapping[str, object],
) -> Mapping[str, object]:
    expected = set(registration.outputs)
    actual = set(outputs)
    if actual != expected:
        raise ValueError(
            f"returned outputs {sorted(actual)!r}; expected {sorted(expected)!r}"
        )
    validated: dict[str, object] = {}
    for name, annotation in registration.outputs.items():
        try:
            validated[name] = _validate_value(annotation, outputs[name])
        except ValidationError as exc:
            raise ValueError(f"returned an invalid {name!r} output: {exc}") from exc
    return validated


def _validate_value(annotation: Any, value: object) -> object:
    if get_origin(annotation) is None and isinstance(annotation, type):
        if not isinstance(value, annotation):
            raise ValueError(
                f"expected {annotation.__name__}, got {type(value).__name__}"
            )
        return value
    return TypeAdapter(annotation).validate_python(value)


def _resolve_source(
    source: str,
    outputs: Mapping[str, Mapping[str, object]],
    initial_inputs: Mapping[str, object],
) -> object:
    if source.startswith("$inputs."):
        return initial_inputs[source.removeprefix("$inputs.")]
    producer_name, separator, output_name = source.partition(".")
    producer_outputs = outputs[producer_name]
    if not separator:
        output_name = next(iter(producer_outputs))
    return producer_outputs[output_name]


def _source_is_available(
    source: str,
    outputs: Mapping[str, Mapping[str, object]],
) -> bool:
    producer_name, separator, output_name = source.partition(".")
    producer_outputs = outputs.get(producer_name)
    if producer_outputs is None:
        return False
    return not separator or output_name in producer_outputs


def _single_or_mapping(values: Mapping[str, object]) -> object:
    if len(values) == 1:
        return next(iter(values.values()))
    return values
