# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import RootModel
from pydantic import model_validator

from metis.engine.codegraph import CodeGraphReference
from metis.sarif.models import SarifPayload

from ..execution.contracts import BUILTIN_STAGE_NAMES
from ..execution.contracts import ResultFormat
from ..execution.contracts import StageName
from ..execution.contracts import annotation_allows_none
from ..execution.compiler import _annotations_compatible
from ..execution.graph import StageConfiguration
from ..execution.graph import _topological_order
from .catalog import StageCatalog
from .contracts import StageRegistration
from .review.models import ReviewCommand
from .review.models import ReviewResult
from .triage.models import TriageRun


@dataclass(frozen=True, slots=True)
class _ResolvedStageContract:
    initial_inputs: Mapping[str, Any]
    stage_inputs: Mapping[str, Any]
    required_execution_inputs: frozenset[str] = frozenset()
    required_outputs: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "initial_inputs",
            MappingProxyType(dict(self.initial_inputs)),
        )
        object.__setattr__(
            self,
            "stage_inputs",
            MappingProxyType(dict(self.stage_inputs)),
        )
        object.__setattr__(
            self,
            "required_outputs",
            MappingProxyType(dict(self.required_outputs)),
        )


BUILTIN_STAGE_CONTRACTS: Mapping[StageName, _ResolvedStageContract] = MappingProxyType(
    {
        "initialize": _ResolvedStageContract({}, {}),
        "review": _ResolvedStageContract(
            {"request": ReviewCommand},
            {},
            required_execution_inputs=frozenset({"review_request"}),
            required_outputs={
                "formats": tuple[ResultFormat, ...],
                "findings": ReviewResult,
                "sarif": SarifPayload,
            },
        ),
        "triage": _ResolvedStageContract(
            {
                "sarif": SarifPayload,
                "request": TriageRun,
                "codegraph": CodeGraphReference | None,
            },
            {
                "sarif": SarifPayload,
                "codegraph": CodeGraphReference | None,
            },
            required_outputs={
                "formats": tuple[ResultFormat, ...],
                "sarif": SarifPayload,
            },
        ),
    }
)


class ExecutionStages(RootModel[dict[StageName, StageConfiguration]]):
    root: dict[StageName, StageConfiguration]

    model_config = ConfigDict(frozen=True)

    @model_validator(mode="after")
    def validate_names(self) -> "ExecutionStages":
        invalid = [name for name in self.root if not name or not name.isidentifier()]
        if invalid:
            raise ValueError(f"Execution graph has invalid stages: {sorted(invalid)!r}")
        return self

    @property
    def initialize(self) -> StageConfiguration | None:
        return self.get("initialize")

    @property
    def review(self) -> StageConfiguration | None:
        return self.get("review")

    @property
    def triage(self) -> StageConfiguration | None:
        return self.get("triage")

    def get(self, name: StageName) -> StageConfiguration | None:
        return self.root.get(name)

    def configured(self) -> tuple[tuple[StageName, StageConfiguration], ...]:
        names = (
            *BUILTIN_STAGE_NAMES,
            *(name for name in self.root if name not in BUILTIN_STAGE_NAMES),
        )
        return tuple((name, self.root[name]) for name in names if name in self.root)


class ExecutionInputs(BaseModel):
    review_request: ReviewCommand | None = None
    sarif: SarifPayload | None = None
    codegraph: CodeGraphReference | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


class ExecutionConfiguration(BaseModel):
    inputs: ExecutionInputs = Field(default_factory=ExecutionInputs)
    stages: ExecutionStages
    node_configuration: dict[str, dict[str, dict[str, Any]]] = Field(
        default_factory=dict
    )

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_pipeline(self) -> "ExecutionConfiguration":
        configured_stages = self.stages.configured()
        enabled: set[StageName] = {name for name, _stage in configured_stages}
        if not enabled:
            raise ValueError("Execution graph must contain a stage")
        contracts = self.stage_contracts()
        required_stage_inputs = {
            name: {
                input_name
                for input_name, annotation in contracts[name].stage_inputs.items()
                if not annotation_allows_none(annotation)
            }
            for name, _stage in configured_stages
        }
        for name, stage in configured_stages:
            contract = contracts[name]
            unknown_inputs = set(stage.inputs) - set(contract.stage_inputs)
            required_inputs = required_stage_inputs[name]
            missing_inputs = required_inputs - set(stage.inputs)
            if missing_inputs:
                raise ValueError(
                    f"Execution stage {name!r} requires inputs: "
                    f"{', '.join(sorted(missing_inputs))}"
                )
            if unknown_inputs:
                raise ValueError(
                    f"Execution stage {name!r} does not accept inputs: "
                    f"{', '.join(sorted(unknown_inputs))}"
                )
            missing_execution_inputs = {
                input_name
                for input_name in contract.required_execution_inputs
                if getattr(self.inputs, input_name) is None
            }
            if missing_execution_inputs:
                input_name = sorted(missing_execution_inputs)[0]
                raise ValueError(
                    f"Execution input {input_name!r} is required by {name}"
                )
            missing = set(stage.depends_on) - enabled
            if missing:
                unavailable = ", ".join(sorted(missing))
                raise ValueError(
                    f"Execution stage {name!r} depends on unavailable stages: "
                    f"{unavailable}"
                )
        for name, stage in configured_stages:
            configured_filenames = [
                node_name
                for node_name, node in stage.nodes.items()
                if node.filename is not None
            ]
            if len(configured_filenames) > 1:
                raise ValueError(
                    f"Execution stage {name!r} configures multiple filenames"
                )
            if configured_filenames:
                if configured_filenames[0] != "result":
                    raise ValueError(
                        f"Execution stage {name!r} filename must be "
                        "configured on its result node"
                    )
            for stage_input_name, source in stage.inputs.items():
                if source.startswith("$inputs."):
                    input_name = source.removeprefix("$inputs.")
                    if input_name not in type(self.inputs).model_fields:
                        raise ValueError(
                            f"Execution stage {name!r} references unknown "
                            f"execution input {input_name!r}"
                        )
                    value = getattr(self.inputs, input_name)
                    if (
                        stage_input_name in required_stage_inputs[name]
                        and value is None
                    ):
                        raise ValueError(
                            f"Execution input {input_name!r} is required by {name}"
                        )
                    if value is not None and not _annotations_compatible(
                        type(value),
                        contracts[name].stage_inputs[stage_input_name],
                    ):
                        raise ValueError(
                            f"Execution stage {name!r} input {stage_input_name!r} "
                            f"is incompatible with {source!r}"
                        )
                    continue
                source_stage, separator, output_name = source.partition(".")
                if not separator or source_stage not in enabled or not output_name:
                    raise ValueError(
                        f"Execution stage {name!r} has invalid input source {source!r}"
                    )
        unknown_config_stages = set(self.node_configuration) - enabled
        if unknown_config_stages:
            names = ", ".join(sorted(unknown_config_stages))
            raise ValueError(
                f"Node configuration refers to unavailable stages: {names}"
            )
        self.stage_order()
        return self

    def stage_order(self) -> tuple[StageName, ...]:
        predecessors: dict[StageName, set[StageName]] = {}
        for stage_name, stage in self.stages.configured():
            dependencies = set(stage.depends_on)
            for source in stage.inputs.values():
                if source.startswith("$inputs."):
                    continue
                source_stage, _, _ = source.partition(".")
                dependencies.add(source_stage)
            predecessors[stage_name] = dependencies
        return _topological_order(
            predecessors,
            tuple(name for name, _stage in self.stages.configured()),
        )

    def stage_contracts(self) -> Mapping[StageName, _ResolvedStageContract]:
        catalog = StageCatalog(BUILTIN_STAGE_CONTRACTS)
        return MappingProxyType(
            {
                name: (
                    BUILTIN_STAGE_CONTRACTS[name]
                    if name in BUILTIN_STAGE_CONTRACTS
                    else _external_stage_contract(catalog.resolve(name))
                )
                for name, _stage in self.stages.configured()
            }
        )

    def selected_nodes(self) -> set[tuple[StageName, str]]:
        return {
            (stage_name, node_name)
            for stage_name, stage in self.stages.configured()
            for node_name in stage.nodes
        }

    def selected_capabilities(self) -> set[str]:
        return {
            capability
            for _stage_name, stage in self.stages.configured()
            for node in stage.nodes.values()
            for capability in node.capabilities
        }


def _external_stage_contract(
    registration: StageRegistration,
) -> _ResolvedStageContract:
    return _ResolvedStageContract(
        registration.contract.inputs,
        registration.contract.inputs,
        required_outputs=registration.contract.required_outputs,
    )
