# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress
from concurrent.futures import CancelledError
from concurrent.futures import FIRST_COMPLETED
from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait
from dataclasses import dataclass
from copy import deepcopy
from dataclasses import replace
from time import perf_counter
from typing import Any

from pydantic import ValidationError

from metis import runlog
from metis.usage import submit_with_current_context

from .compiler import StagePlan
from .compiler import _PlannedNode
from .contracts import ExecutionDiagnostic
from .contracts import ExecutionStatus
from .contracts import NodeContext
from .contracts import NodeInvocation
from .contracts import NodeRegistration
from .contracts import NodeResult
from .contracts import StageName
from .contracts import annotation_allows_none
from .contracts import annotation_adapter


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
    *,
    executor: ThreadPoolExecutor | None = None,
) -> StageRun:
    with runlog.span(
        "stage",
        stage_name,
        lambda: {
            "nodes": [
                {
                    "name": node.name,
                    "dependencies": sorted(node.dependencies),
                    "required_dependencies": sorted(node.required_dependencies),
                    "capabilities": sorted(node.capabilities),
                }
                for node in planned.nodes
            ],
            "output_bindings": dict(planned.output_bindings),
            "initial_inputs": initial_inputs,
        },
    ) as stage_span:
        outputs: dict[str, Mapping[str, object]] = {}
        diagnostics_by_node: dict[str, tuple[ExecutionDiagnostic, ...]] = {}
        status = ExecutionStatus.OK
        failed: set[str] = set()
        completed: set[str] = set()
        pending = {node.name for node in planned.nodes}
        stage_started = perf_counter()
        if context.runtime.is_cancelled():
            raise CancelledError("Execution stage was cancelled")
        stage_context = replace(context, runtime=context.runtime._with_cancellation())
        _progress(
            stage_context,
            {"event": "execution_stage_start", "stage": stage_name},
        )
        owns_executor = executor is None
        if executor is None:
            executor = ThreadPoolExecutor(
                max_workers=min(context.runtime.max_workers, len(planned.nodes)),
                thread_name_prefix="metis-node",
            )
        running: dict[Future[NodeResult], _PlannedNode] = {}
        failure: BaseException | None = None
        try:
            while pending or running:
                if stage_context.runtime.is_cancelled():
                    raise CancelledError("Execution stage was cancelled")
                for node in planned.nodes:
                    if node.name not in pending or not node.dependencies <= completed:
                        continue
                    pending.remove(node.name)
                    if node.required_dependencies & failed:
                        _skip_node(stage_name, node, stage_context)
                        failed.add(node.name)
                        completed.add(node.name)
                        continue
                    running[
                        submit_with_current_context(
                            executor,
                            _run_node,
                            stage_name,
                            node,
                            stage_context,
                            dict(outputs),
                            initial_inputs,
                        )
                    ] = node
                if not running:
                    if pending:
                        raise AssertionError("Execution stage scheduler stalled")
                    break
                finished, _unfinished = wait(
                    tuple(running),
                    return_when=FIRST_COMPLETED,
                    timeout=0.1,
                )
                for future in finished:
                    node = running.pop(future)
                    node_run = future.result()
                    completed.add(node.name)
                    diagnostics_by_node[node.name] = node_run.diagnostics
                    if node_run.status is ExecutionStatus.ERROR:
                        failed.add(node.name)
                        continue
                    outputs[node.name] = node_run.outputs
                    if (
                        node_run.status is ExecutionStatus.INCONCLUSIVE
                        and status is ExecutionStatus.OK
                    ):
                        status = ExecutionStatus.INCONCLUSIVE
            if stage_context.runtime.is_cancelled():
                raise CancelledError("Execution stage was cancelled")
        except BaseException as exc:
            failure = exc
        finally:
            while True:
                try:
                    if failure is not None:
                        stage_context.jobs.cancel()
                        for future in running:
                            future.cancel()
                    # Drain only this stage, for either executor ownership path.
                    # done() includes cancelled futures removed from the work queue.
                    for future in running:
                        while not future.done():
                            with suppress(BaseException):
                                future.result()
                    if owns_executor:
                        executor.shutdown(wait=True, cancel_futures=True)
                    break
                except BaseException as exc:
                    # Shutdown is idempotent; finish cleanup before raising the first error.
                    if failure is None:
                        failure = exc
        if failure is not None:
            raise failure
        diagnostics = [
            diagnostic
            for node in planned.nodes
            for diagnostic in diagnostics_by_node.get(node.name, ())
        ]
        if failed:
            tolerated_failures = {
                source.partition(".")[0]
                for node in planned.nodes
                for input_name, binding in node.input_bindings.items()
                if isinstance(binding, tuple)
                and input_name not in node.registration.required_when_bound
                for source in binding
                if not source.startswith("$inputs.")
            }
            output_producers = {
                source.partition(".")[0] for source in planned.output_bindings.values()
            }
            fatal_failures = (failed - tolerated_failures) | (failed & output_producers)
            status = (
                ExecutionStatus.ERROR
                if fatal_failures
                else ExecutionStatus.INCONCLUSIVE
            )
        if not planned.output_bindings:
            stage_outputs: dict[str, object] = {
                node.name: _single_or_mapping(outputs[node.name])
                for node in planned.nodes
                if node.name in outputs
            }
        else:
            stage_outputs = {
                name: _resolve_source(source, outputs, {})
                for name, source in planned.output_bindings.items()
                if _source_is_available(source, outputs)
            }
        _progress(
            stage_context,
            {
                "event": "execution_stage_end",
                "stage": stage_name,
                "status": status.value,
                "duration_seconds": perf_counter() - stage_started,
            },
        )
        if stage_context.runtime.is_cancelled():
            raise CancelledError("Execution stage was cancelled")
        stage_span.end(
            status=status.value,
            attributes={"outputs": stage_outputs, "diagnostics": diagnostics},
        )
        if stage_context.runtime.is_cancelled():
            raise CancelledError("Execution stage was cancelled")
        return StageRun(status, stage_outputs, tuple(diagnostics))


def _run_node(
    stage_name: StageName,
    node: _PlannedNode,
    context: NodeContext,
    outputs: Mapping[str, Mapping[str, object]],
    initial_inputs: Mapping[str, object],
) -> NodeResult:
    model = node.definition.model or context.runtime.model
    token_counter_for_model = context.runtime.token_counter_for_model
    max_concurrency = min(
        node.definition.max_concurrency or context.runtime.max_workers,
        context.runtime.max_workers,
    )
    with runlog.span(
        "node",
        f"{stage_name}.{node.name}",
        lambda: {
            "stage": stage_name,
            "node": node.name,
            "configuration": node.configuration,
            "input_bindings": dict(node.input_bindings),
            "capabilities": sorted(node.capabilities),
            "formats": node.definition.formats,
            "filename": node.definition.filename,
            "model": model,
            "max_concurrency": max_concurrency,
        },
    ) as node_span:
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
        inputs: dict[str, object] = {}
        result = None
        node_outputs: Mapping[str, object] = {}
        node_error: Exception | None = None
        diagnostics: tuple[ExecutionDiagnostic, ...] = ()
        try:
            if context.runtime.is_cancelled():
                raise CancelledError("Execution stage was cancelled")
            inputs = _resolve_inputs(node, outputs, initial_inputs)
            progress = context.callbacks.progress
            node_context = replace(
                context,
                capabilities=node.capabilities,
                callbacks=(
                    replace(
                        context.callbacks,
                        progress=lambda event: progress(
                            {**event, "stage": stage_name, "node": node.name}
                        ),
                    )
                    if progress is not None
                    else context.callbacks
                ),
                runtime=replace(
                    context.runtime,
                    model=model,
                    max_workers=max_concurrency,
                    token_counter=(
                        token_counter_for_model(model)
                        if token_counter_for_model is not None
                        else context.runtime.token_counter
                    ),
                    jobs=context.jobs.limit(max_concurrency),
                )._with_cancellation(),
            )
            result = node.registration.execute(
                NodeInvocation(
                    configuration=node.registration.configuration.model_validate(
                        deepcopy(dict(node.configuration_values))
                    ),
                    inputs=inputs,
                    context=node_context,
                    formats=node.definition.formats,
                    filename=node.definition.filename,
                )
            )
            if not isinstance(result, NodeResult):
                raise TypeError("handler must return a NodeResult")
            if not isinstance(result.status, ExecutionStatus):
                raise TypeError("NodeResult status must be an ExecutionStatus")
            if not isinstance(result.outputs, Mapping):
                raise TypeError("NodeResult outputs must be a mapping")
            if not isinstance(result.diagnostics, tuple) or not all(
                isinstance(diagnostic, ExecutionDiagnostic)
                and isinstance(diagnostic.code, str)
                and isinstance(diagnostic.message, str)
                and isinstance(diagnostic.severity, str)
                and diagnostic.severity in ("warning", "error")
                for diagnostic in result.diagnostics
            ):
                raise TypeError(
                    "NodeResult diagnostics must be ExecutionDiagnostic values"
                )
            diagnostics = result.diagnostics
            node_status = result.status
            if node_status is not ExecutionStatus.ERROR:
                node_outputs = _validate_outputs(
                    node.registration,
                    result.outputs,
                )
                if node_context.runtime.is_cancelled():
                    raise CancelledError("Execution node was cancelled")
        except CancelledError:
            raise
        except Exception as exc:
            node_error = exc
            node_status = ExecutionStatus.ERROR
            diagnostics = (
                *diagnostics,
                ExecutionDiagnostic(
                    code="execution.node_failed",
                    message=f"Execution node {stage_name}.{node.name} failed: {exc}",
                ),
            )
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
        if context.callbacks.diagnostic is not None:
            for diagnostic in diagnostics:
                context.callbacks.diagnostic(diagnostic)
        # Job failures also signal their scope; preserve those as node errors.
        if (
            node_status is not ExecutionStatus.ERROR
            and node_context.runtime.is_cancelled()
        ):
            raise CancelledError("Execution node was cancelled")
        node_span.end(
            status=node_status.value,
            attributes={
                "inputs": inputs,
                "outputs": node_outputs,
                "diagnostics": diagnostics,
            },
            exc=node_error,
        )
        if (
            node_status is not ExecutionStatus.ERROR
            and node_context.runtime.is_cancelled()
        ):
            raise CancelledError("Execution node was cancelled")
        return NodeResult(node_outputs, node_status, diagnostics)


def _skip_node(
    stage_name: StageName,
    node: _PlannedNode,
    context: NodeContext,
) -> None:
    with runlog.span(
        "node",
        f"{stage_name}.{node.name}",
        {
            "stage": stage_name,
            "node": node.name,
            "dependencies": sorted(node.dependencies),
        },
    ) as skipped_span:
        skipped_span.end(
            status="cancelled",
            attributes={"reason": "dependency_failed"},
        )
    _progress(
        context,
        {
            "event": "execution_node_skipped",
            "stage": stage_name,
            "node": node.name,
            "reason": "dependency_failed",
        },
    )


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
                _resolve_source(item, outputs, initial_inputs)
                for item in source
                if item.startswith("$inputs.") or _source_is_available(item, outputs)
            )
        elif source.startswith("$inputs."):
            value = initial_inputs.get(source.removeprefix("$inputs."))
        elif not _source_is_available(source, outputs) and annotation_allows_none(
            annotation
        ):
            value = None
        else:
            value = _resolve_source(source, outputs, initial_inputs)
        if (
            isinstance(source, tuple)
            and not value
            and not annotation_allows_none(annotation)
        ):
            raise ValueError(f"input {input_name!r} requires at least one value")
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
    return annotation_adapter(annotation).validate_python(value, strict=True)


def _resolve_source(
    source: str,
    outputs: Mapping[str, Mapping[str, object]],
    initial_inputs: Mapping[str, object],
) -> object:
    if source.startswith("$inputs."):
        return initial_inputs.get(source.removeprefix("$inputs."))
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
