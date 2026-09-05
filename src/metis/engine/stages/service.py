# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Mapping
from concurrent.futures import CancelledError
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from functools import partial
from threading import Condition
from threading import Event
from typing import TYPE_CHECKING
from typing import Any
from typing import cast

from metis import runlog
from metis.engine.concurrency import JobScheduler
from metis.engine.concurrency import serialized_progress_callback
from metis.engine.codegraph import CodeGraphReference
from metis.engine.llm_runner import JsonPromptRunner
from metis.runtime_settings import TriageOptions
from metis.sarif.models import SarifPayload
from metis.utils import count_tokens

from ..execution.catalog import NodeCatalog
from ..execution.compiler import StagePlan
from ..execution.compiler import _annotations_compatible
from ..execution.compiler import compile_stage
from ..execution.contracts import ExecutionDiagnostic
from ..execution.contracts import ExecutionResult
from ..execution.contracts import ExecutionStatus
from ..execution.contracts import NodeCallbacks
from ..execution.contracts import NodeCodeGraphs
from ..execution.contracts import NodeContext
from ..execution.contracts import NodeRegistration
from ..execution.contracts import NodeRuntime
from ..execution.contracts import StageName
from ..execution.contracts import annotation_allows_none
from ..execution.runner import run_stage
from ..execution.runner import _validate_value
from .configuration import ExecutionConfiguration
from .review.models import ReviewCommand
from .triage.contracts import TriageAdjudicator
from .triage.models import TriageRun

if TYPE_CHECKING:
    from importlib import metadata

    from metis.engine.repository import EngineRepository
    from metis.engine.runtime import EngineConfig


_active_services: ContextVar[tuple[tuple[ExecutionGraphService, Event], ...]] = (
    ContextVar("metis_active_execution_services", default=())
)


class ExecutionGraphService:
    def __init__(
        self,
        configuration: ExecutionConfiguration,
        *,
        engine_config: EngineConfig,
        repository: EngineRepository,
        capabilities: Mapping[str, object],
        prompt_runner: JsonPromptRunner,
        codegraphs: NodeCodeGraphs,
        triage_adjudicator: TriageAdjudicator | None,
        triage_options: TriageOptions,
        registrations: Iterable[NodeRegistration],
        entry_points: tuple[metadata.EntryPoint, ...] | None = None,
    ) -> None:
        self.configuration = configuration
        self._stages = {
            name: stage.model_copy(deep=True)
            for name, stage in configuration.stages.configured()
        }
        self._stage_order = configuration.stage_order()
        self._inputs = configuration.inputs.model_copy(deep=True)
        self._engine_config = engine_config
        self._repository = repository
        self._prompt_runner = prompt_runner
        self._codegraphs = codegraphs
        self._triage_adjudicator = triage_adjudicator
        self._triage_options = triage_options
        catalog = NodeCatalog(registrations, entry_points)
        self._plans: dict[StageName, StagePlan] = {}
        self._contracts = configuration.stage_contracts()
        self._validate_configuration(catalog, capabilities)
        self._node_executor = ThreadPoolExecutor(
            max_workers=engine_config.max_active_nodes,
            thread_name_prefix="metis-node",
        )
        self._scheduler = JobScheduler(engine_config.max_workers)
        self._jobs = self._scheduler.limit(engine_config.max_workers)
        self._condition = Condition()
        self._closed = False
        self._active_executions: set[Event] = set()

    def _check_reentry(self, action: str) -> None:
        # Called with the lifecycle condition held. Context markers only guard
        # reentry; cancellation is owned by each execution's Event.
        if any(
            service is self and execution in self._active_executions
            for service, execution in _active_services.get()
        ):
            raise RuntimeError(
                f"Cannot {action} the execution service from an active execution"
            )

    def check_can_close(self) -> None:
        with self._condition:
            self._check_reentry("close")

    def close(self) -> None:
        self.check_can_close()
        with self._condition:
            self._closed = True
            for cancellation in self._active_executions:
                cancellation.set()
            self._condition.notify_all()
        first_error: BaseException | None = None
        while True:
            try:
                self._scheduler.close()
                with self._condition:
                    self._condition.wait_for(lambda: not self._active_executions)
                self._node_executor.shutdown(wait=True, cancel_futures=True)
            except BaseException as exc:
                # Shutdown is idempotent; finish draining before callers close capabilities.
                if first_error is None:
                    first_error = exc
            else:
                break
        if first_error is not None:
            raise first_error

    def execute_initialize(
        self,
        *,
        callbacks: Mapping[str, object] | None = None,
    ) -> ExecutionResult:
        return self._execute_target("initialize", callbacks=callbacks)

    def execute_review(
        self,
        command: ReviewCommand,
        *,
        callbacks: Mapping[str, object] | None = None,
    ) -> ExecutionResult:
        return self._execute_target(
            "review", callbacks=callbacks, initial_inputs={"request": command}
        )

    def execute_triage(
        self,
        sarif: dict[str, Any] | SarifPayload,
        *,
        codegraph: CodeGraphReference | None = None,
        include_triaged: bool | None = None,
        callbacks: Mapping[str, object] | None = None,
    ) -> ExecutionResult:
        return self._execute_target(
            "triage",
            callbacks=callbacks,
            initial_inputs={
                "sarif": SarifPayload.model_validate(sarif),
                "codegraph": codegraph,
            },
            include_triaged=include_triaged,
        )

    def execute_graph(
        self,
        *,
        include_triaged: bool | None = None,
        callbacks: Mapping[str, object] | None = None,
    ) -> ExecutionResult:
        return self._execute_stages(
            self._stage_order,
            callbacks=callbacks,
            include_triaged=include_triaged,
        )

    def _execute_target(
        self,
        target: StageName,
        *,
        callbacks: Mapping[str, object] | None,
        initial_inputs: Mapping[str, Any] | None = None,
        include_triaged: bool | None = None,
    ) -> ExecutionResult:
        if target not in self._stages:
            return _unavailable_stage(target)
        selected: set[StageName] = set()
        pending = [target]
        while pending:
            name = pending.pop()
            if name in selected:
                continue
            selected.add(name)
            stage = self._stages[name]
            pending.extend(stage.depends_on)
            pending.extend(
                source.partition(".")[0]
                for port, source in stage.inputs.items()
                if not source.startswith("$inputs.")
                and not (name == target and port in (initial_inputs or {}))
            )
        return self._execute_stages(
            tuple(name for name in self._stage_order if name in selected),
            callbacks=callbacks,
            include_triaged=include_triaged,
            overrides={target: initial_inputs or {}},
        )

    def _execute_stages(
        self,
        stage_order: tuple[StageName, ...],
        *,
        callbacks: Mapping[str, object] | None,
        include_triaged: bool | None,
        overrides: Mapping[StageName, Mapping[str, Any]] | None = None,
    ) -> ExecutionResult:
        cancellation = Event()
        with self._condition:
            self._check_reentry("start nested execution on")
            self._condition.wait_for(
                lambda: (
                    self._closed
                    or len(self._active_executions)
                    < self._engine_config.max_concurrent_executions
                )
            )
            if self._closed:
                raise RuntimeError("Execution service is closed")
            self._active_executions.add(cancellation)
        token = _active_services.set((*_active_services.get(), (self, cancellation)))
        try:
            runlog.event(
                "execution.topology",
                {"stage_order": stage_order, "configuration": self.configuration},
            )
            outputs: dict[str, Any] = {}
            diagnostics: list[ExecutionDiagnostic] = []
            status = ExecutionStatus.OK
            for stage_name in stage_order:
                if cancellation.is_set():
                    raise CancelledError("Execution was cancelled")
                result = self._execute_configured_stage(
                    stage_name,
                    outputs,
                    callbacks=callbacks,
                    initial_inputs=(overrides or {}).get(stage_name),
                    include_triaged=include_triaged,
                    cancellation=cancellation,
                )
                diagnostics.extend(result.diagnostics)
                # Failed stages can still publish validated independent outputs.
                outputs.update(
                    (name, values)
                    for name, values in result.outputs.items()
                    if values or result.status is not ExecutionStatus.ERROR
                )
                if result.status is ExecutionStatus.ERROR:
                    return ExecutionResult(result.status, outputs, tuple(diagnostics))
                if result.status is ExecutionStatus.INCONCLUSIVE:
                    status = ExecutionStatus.INCONCLUSIVE
            if cancellation.is_set():
                raise CancelledError("Execution was cancelled")
            return ExecutionResult(status, outputs, tuple(diagnostics))

        finally:
            _active_services.reset(token)
            with self._condition:
                self._active_executions.remove(cancellation)
                self._condition.notify_all()

    def _execute_configured_stage(
        self,
        stage_name: StageName,
        outputs: Mapping[str, Any],
        *,
        callbacks: Mapping[str, object] | None,
        initial_inputs: Mapping[str, Any] | None = None,
        include_triaged: bool | None = None,
        cancellation: Event,
    ) -> ExecutionResult:
        stage = self._stages[stage_name]
        overrides = initial_inputs or {}
        inputs: dict[str, Any] = {
            name: None
            for name, annotation in self._contracts[stage_name].stage_inputs.items()
            if annotation_allows_none(annotation)
        }
        inputs.update(
            (name, _resolve_stage_input(binding, outputs, self._inputs))
            for name, binding in stage.inputs.items()
            if name not in overrides
        )
        if stage_name == "review":
            inputs["request"] = self._inputs.review_request
        inputs.update(overrides)
        for name, annotation in self._contracts[stage_name].stage_inputs.items():
            try:
                inputs[name] = _validate_value(annotation, inputs[name])
            except CancelledError:
                raise
            except Exception as exc:
                return ExecutionResult(
                    ExecutionStatus.ERROR,
                    {stage_name: {}},
                    (
                        ExecutionDiagnostic(
                            code="execution.stage_input_invalid",
                            message=(
                                f"Execution stage {stage_name!r} input {name!r} "
                                f"is invalid: {exc}"
                            ),
                        ),
                    ),
                )
        if stage_name == "triage":
            inputs["request"] = TriageRun.from_payload(
                cast(SarifPayload, inputs["sarif"]),
                include_triaged=(
                    self._triage_options.include_triaged
                    if include_triaged is None
                    else include_triaged
                ),
            )
        run = run_stage(
            stage_name,
            self._plans[stage_name],
            self._context(stage_name, callbacks=callbacks, cancellation=cancellation),
            inputs,
            executor=self._node_executor,
        )
        stage_outputs = dict(run.outputs)
        diagnostics = list(run.diagnostics)
        status = run.status
        for name, annotation in self._contracts[stage_name].required_outputs.items():
            if name not in stage_outputs:
                continue
            try:
                stage_outputs[name] = _validate_value(annotation, stage_outputs[name])
            except CancelledError:
                raise
            except Exception as exc:
                del stage_outputs[name]
                status = ExecutionStatus.ERROR
                diagnostics.append(
                    ExecutionDiagnostic(
                        code="execution.stage_output_invalid",
                        message=(
                            f"Execution stage {stage_name!r} output {name!r} "
                            f"is invalid: {exc}"
                        ),
                    )
                )
        return ExecutionResult(status, {stage_name: stage_outputs}, tuple(diagnostics))

    def _validate_configuration(
        self,
        catalog: NodeCatalog,
        capabilities: Mapping[str, object],
    ) -> None:
        for stage_name in self._stage_order:
            contract = self._contracts[stage_name]
            stage = self._stages[stage_name]
            initial_inputs = dict(contract.initial_inputs)
            for name in contract.stage_inputs:
                source = stage.inputs.get(name)
                if source is None:
                    initial_inputs[name] = type(None)
                elif source.startswith("$inputs."):
                    value = getattr(self._inputs, source.removeprefix("$inputs."))
                    initial_inputs[name] = type(value)
                else:
                    source_stage, _, source_output = source.partition(".")
                    source_plan = self._plans.get(source_stage)
                    if source_plan is not None and source_output in (
                        source_plan.output_annotations
                    ):
                        initial_inputs[name] = source_plan.output_annotations[
                            source_output
                        ]
            self._plans[stage_name] = compile_stage(
                catalog,
                stage_name,
                stage,
                self.configuration.node_configuration.get(stage_name, {}),
                initial_inputs,
                capabilities,
            )
            plan = self._plans[stage_name]
            if not plan.output_annotations:
                raise ValueError(f"Execution stage {stage_name!r} must declare outputs")
            required_outputs = contract.required_outputs
            missing_outputs = set(required_outputs) - set(plan.output_annotations)
            if missing_outputs:
                names = ", ".join(sorted(missing_outputs))
                raise ValueError(
                    f"Execution stage {stage_name!r} must declare outputs: {names}"
                )
            expected_outputs = dict(required_outputs)
            if (
                stage_name in {"review", "triage"}
                and "filename" in plan.output_annotations
            ):
                expected_outputs["filename"] = str | None
            for output_name, annotation in expected_outputs.items():
                if not _annotations_compatible(
                    plan.output_annotations[output_name],
                    annotation,
                ):
                    raise ValueError(
                        f"Execution stage {stage_name!r} output {output_name!r} "
                        "has an incompatible type"
                    )
            for input_name, source in stage.inputs.items():
                if source.startswith("$inputs."):
                    continue
                source_stage, _, source_output = source.partition(".")
                source_plan = self._plans[source_stage]
                if source_output not in source_plan.output_annotations:
                    raise ValueError(
                        f"Execution stage {stage_name!r} input {input_name!r} "
                        f"references unknown output {source!r}"
                    )
                source_annotation = source_plan.output_annotations[source_output]
                target_annotation = self._contracts[stage_name].stage_inputs[input_name]
                if not _annotations_compatible(
                    source_annotation,
                    target_annotation,
                ):
                    raise ValueError(
                        f"Execution stage {stage_name!r} input {input_name!r} "
                        f"is incompatible with {source!r}"
                    )

    def _context(
        self,
        stage: StageName,
        *,
        callbacks: Mapping[str, object] | None = None,
        cancellation: Event,
    ) -> NodeContext:
        llm_provider = self._engine_config.llm_provider

        def token_counter_for_model(model: str):
            return partial(llm_provider.count_tokens, model=model)

        return NodeContext(
            stage=stage,
            codebase_path=self._engine_config.codebase_path,
            repository=self._repository,
            capabilities={},
            prompts=self._prompt_runner,
            codegraphs=self._codegraphs,
            runtime=NodeRuntime(
                model=self._engine_config.llama_query_model,
                max_workers=self._engine_config.max_workers,
                max_token_length=self._engine_config.max_token_length,
                token_counter=token_counter_for_model(
                    self._engine_config.llama_query_model
                )
                if llm_provider is not None
                else count_tokens,
                token_counter_for_model=(
                    token_counter_for_model if llm_provider is not None else None
                ),
                model_tool_max_rounds=(
                    self._engine_config.capability_settings.model_tools.max_rounds
                ),
                chat_model_kwargs=dict(self._engine_config.chat_model_kwargs),
                jobs=self._jobs.with_cancellation(cancellation),
                is_cancelled=cancellation.is_set,
            ),
            callbacks=_node_callbacks(stage, callbacks),
            triage=self._triage_adjudicator,
        )


def _resolve_stage_input(
    source: str,
    outputs: Mapping[str, Any],
    configured_inputs: object,
) -> object:
    if source.startswith("$inputs."):
        return getattr(configured_inputs, source.removeprefix("$inputs."))
    stage_name, _, output_name = source.partition(".")
    return outputs[stage_name][output_name]


def _node_callbacks(
    stage: StageName,
    callbacks: Mapping[str, object] | None,
) -> NodeCallbacks:
    values = callbacks or {}
    checkpoint_callback = values.get(
        "review_checkpoint_callback" if stage == "review" else "checkpoint_callback"
    )
    return NodeCallbacks(
        progress=serialized_progress_callback(
            _mapping_callback("progress", cast(Any, values.get("progress_callback")))
        ),
        debug=_mapping_callback("debug", cast(Any, values.get("debug_callback"))),
        checkpoint=(
            cast(Any, checkpoint_callback)
            if stage == "review"
            else _checkpoint_callback(cast(Any, checkpoint_callback))
        ),
        resume=(
            cast(Any, values.get("review_resume_callback"))
            if stage == "review"
            else None
        ),
        diagnostic=_diagnostic_callback(cast(Any, values.get("diagnostic_callback"))),
    )


def _mapping_callback(name: str, callback):
    if not runlog.is_enabled():
        return callback

    def invoke(payload):
        runlog.event(
            name, payload if isinstance(payload, Mapping) else {"value": payload}
        )
        if callable(callback):
            callback(payload)

    return invoke


def _checkpoint_callback(callback):
    if not runlog.is_enabled():
        return callback

    def invoke(payload, processed, total):
        runlog.event(
            "checkpoint",
            {"processed": processed, "total": total, "payload": payload},
        )
        if callable(callback):
            callback(payload, processed, total)

    return invoke


def _diagnostic_callback(callback):
    if not runlog.is_enabled():
        return callback

    def invoke(diagnostic):
        runlog.event("diagnostic", {"diagnostic": diagnostic})
        if callable(callback):
            callback(diagnostic)

    return invoke


def _unavailable_stage(stage: str) -> ExecutionResult:
    return ExecutionResult(
        ExecutionStatus.ERROR,
        {},
        (
            ExecutionDiagnostic(
                code="execution.stage_unavailable",
                message=f"Execution stage {stage!r} is not configured",
            ),
        ),
    )
