# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Mapping
from typing import TYPE_CHECKING
from typing import Any
from typing import assert_never
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
from ..execution.graph import StageConfiguration
from ..execution.runner import run_stage
from .configuration import STAGE_CONTRACTS
from .configuration import ExecutionConfiguration
from .review.models import ReviewCommand
from .triage.contracts import TriageAdjudicator
from .triage.models import TriageRun

if TYPE_CHECKING:
    from importlib import metadata

    from metis.engine.repository import EngineRepository
    from metis.engine.runtime import EngineConfig


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
        self._engine_config = engine_config
        self._repository = repository
        self._prompt_runner = prompt_runner
        self._codegraphs = codegraphs
        self._triage_adjudicator = triage_adjudicator
        self._triage_options = triage_options
        catalog = NodeCatalog(registrations, entry_points)
        self._plans: dict[StageName, StagePlan] = {}
        self._validate_configuration(catalog, capabilities)
        self._scheduler = JobScheduler(engine_config.max_workers)
        self._jobs = self._scheduler.limit(engine_config.max_workers)

    def close(self) -> None:
        self._scheduler.close()

    def execute_initialize(
        self,
        *,
        callbacks: Mapping[str, object] | None = None,
    ) -> ExecutionResult:
        stage = self.configuration.stages.initialize
        if stage is None:
            return _unavailable_stage("initialize")
        run = run_stage(
            "initialize",
            self._plans["initialize"],
            self._context("initialize", callbacks=callbacks),
            {},
        )
        return ExecutionResult(
            run.status,
            {"initialize": run.outputs},
            run.diagnostics,
        )

    def execute_review(
        self,
        command: ReviewCommand,
        *,
        callbacks: Mapping[str, object] | None = None,
    ) -> ExecutionResult:
        stage = self.configuration.stages.review
        if stage is None:
            return _unavailable_stage("review")
        run = run_stage(
            "review",
            self._plans["review"],
            self._context("review", callbacks=callbacks),
            {"request": command},
        )
        return ExecutionResult(run.status, {"review": run.outputs}, run.diagnostics)

    def execute_triage(
        self,
        sarif: dict[str, Any] | SarifPayload,
        *,
        codegraph: CodeGraphReference | None = None,
        include_triaged: bool | None = None,
        callbacks: Mapping[str, object] | None = None,
    ) -> ExecutionResult:
        stage = self.configuration.stages.triage
        if stage is None:
            return _unavailable_stage("triage")
        callbacks = callbacks or {}
        payload = SarifPayload.model_validate(sarif)
        include_triaged = (
            self._triage_options.include_triaged
            if include_triaged is None
            else include_triaged
        )
        triage_run = TriageRun.from_payload(
            payload,
            include_triaged=include_triaged,
        )
        run = run_stage(
            "triage",
            self._plans["triage"],
            self._context("triage", callbacks=callbacks),
            {
                "sarif": payload,
                "request": triage_run,
                "codegraph": codegraph,
            },
        )
        return ExecutionResult(run.status, {"triage": run.outputs}, run.diagnostics)

    def execute_graph(
        self,
        *,
        include_triaged: bool | None = None,
        callbacks: Mapping[str, object] | None = None,
    ) -> ExecutionResult:
        runlog.event(
            "execution.topology",
            {
                "stage_order": self.configuration.stage_order(),
                "configuration": self.configuration,
            },
        )
        outputs: dict[str, Any] = {}
        diagnostics: list[ExecutionDiagnostic] = []
        status = ExecutionStatus.OK
        for stage_name in self.configuration.stage_order():
            if stage_name == "initialize":
                result = self.execute_initialize(callbacks=callbacks)
            elif stage_name == "review":
                result = self.execute_review(
                    cast(ReviewCommand, self.configuration.inputs.review_request),
                    callbacks=callbacks,
                )
            elif stage_name == "triage":
                result = self._execute_configured_triage(
                    outputs,
                    include_triaged=include_triaged,
                    callbacks=callbacks,
                )
            else:
                assert_never(stage_name)
            diagnostics.extend(result.diagnostics)
            if result.status is ExecutionStatus.ERROR:
                return ExecutionResult(result.status, outputs, tuple(diagnostics))
            outputs.update(result.outputs)
            if result.status is ExecutionStatus.INCONCLUSIVE:
                status = ExecutionStatus.INCONCLUSIVE
        return ExecutionResult(status, outputs, tuple(diagnostics))

    def _validate_configuration(
        self,
        catalog: NodeCatalog,
        capabilities: Mapping[str, object],
    ) -> None:
        stage_order = self.configuration.stage_order()
        for stage_name in stage_order:
            contract = STAGE_CONTRACTS[stage_name]
            stage = cast(StageConfiguration, self.configuration.stages.get(stage_name))
            self._plans[stage_name] = compile_stage(
                catalog,
                stage_name,
                stage,
                self.configuration.node_configuration.get(stage_name, {}),
                contract.initial_inputs,
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
            for output_name, annotation in required_outputs.items():
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
                source_plan = self._plans[cast(StageName, source_stage)]
                if source_output not in source_plan.output_annotations:
                    raise ValueError(
                        f"Execution stage {stage_name!r} input {input_name!r} "
                        f"references unknown output {source!r}"
                    )
                source_annotation = source_plan.output_annotations[source_output]
                target_annotation = STAGE_CONTRACTS[stage_name].stage_inputs[input_name]
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
    ) -> NodeContext:
        llm_provider = self._engine_config.llm_provider
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
                token_counter=(
                    llm_provider.count_tokens
                    if llm_provider is not None
                    else count_tokens
                ),
                model_tool_max_rounds=(
                    self._engine_config.capability_settings.model_tools.max_rounds
                ),
                chat_model_kwargs=dict(self._engine_config.chat_model_kwargs),
                jobs=self._jobs,
            ),
            callbacks=_node_callbacks(stage, callbacks),
            triage=self._triage_adjudicator,
        )

    def _execute_configured_triage(
        self,
        outputs: Mapping[str, Any],
        *,
        include_triaged: bool | None,
        callbacks: Mapping[str, object] | None,
    ) -> ExecutionResult:
        stage = cast(StageConfiguration, self.configuration.stages.triage)
        sarif = cast(
            SarifPayload,
            _resolve_stage_input(
                stage.inputs["sarif"],
                outputs,
                self.configuration.inputs,
            ),
        )
        codegraph = None
        if codegraph_binding := stage.inputs.get("codegraph"):
            codegraph = cast(
                CodeGraphReference | None,
                _resolve_stage_input(
                    codegraph_binding,
                    outputs,
                    self.configuration.inputs,
                ),
            )
        return self.execute_triage(
            sarif,
            codegraph=codegraph,
            include_triaged=include_triaged,
            callbacks=callbacks,
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
