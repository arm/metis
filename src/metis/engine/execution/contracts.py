# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from types import MappingProxyType
from typing import Any
from typing import Literal
from typing import Protocol
from typing import TYPE_CHECKING
from typing import get_args

from pydantic import BaseModel
from pydantic import ConfigDict

from metis.engine.llm_runner import JsonPromptRequest
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import CodeGraphReference

if TYPE_CHECKING:
    from metis.engine.stages.triage.contracts import TriageAdjudicator

StageName = Literal["initialize", "review", "triage"]
STAGE_NAMES: tuple[StageName, ...] = get_args(StageName)
ResultFormat = Literal["sarif", "json", "html", "csv"]
NodeHandler = Callable[["NodeInvocation"], "NodeResult"]
EXECUTION_NODE_API_VERSION = 1


def annotation_allows_none(annotation: Any) -> bool:
    return type(None) in get_args(annotation)


class NodeRepository(Protocol):
    def get_code_files(
        self,
        *,
        include_suffixed_sources: bool = False,
        dir_path: str | None = None,
    ) -> list[str]: ...

    def get_language_name_for_path(self, path: str) -> str | None: ...


class NodePromptRunner(Protocol):
    def invoke(self, request: JsonPromptRequest) -> object: ...


class NodeCodeGraphs(Protocol):
    def materialize(
        self,
        *,
        progress_callback: Callable[[dict[str, object]], None] | None = None,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
    ) -> CodeGraphReference: ...

    def load(self, reference: CodeGraphReference) -> CodeGraph: ...


class EmptyNodeConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExecutionStatus(str, Enum):
    OK = "ok"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class CapabilityRequirement(str, Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"


@dataclass(frozen=True, slots=True)
class ExecutionDiagnostic:
    code: str
    message: str
    severity: Literal["warning", "error"] = "error"


ProgressCallback = Callable[[Mapping[str, object]], None]
DebugCallback = Callable[[Mapping[str, object]], None]
CheckpointCallback = Callable[[dict[str, Any], int, int], None]
DiagnosticCallback = Callable[[ExecutionDiagnostic], None]


@dataclass(frozen=True, slots=True)
class NodeCallbacks:
    progress: ProgressCallback | None = None
    debug: DebugCallback | None = None
    checkpoint: CheckpointCallback | None = None
    diagnostic: DiagnosticCallback | None = None


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    status: ExecutionStatus
    outputs: Mapping[str, Any]
    diagnostics: tuple[ExecutionDiagnostic, ...] = ()


@dataclass(frozen=True, slots=True)
class NodeRuntime:
    model: str
    max_workers: int
    max_token_length: int
    chat_model_kwargs: Mapping[str, object]
    model_tool_max_rounds: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "chat_model_kwargs",
            MappingProxyType(dict(self.chat_model_kwargs)),
        )


@dataclass(frozen=True, slots=True)
class NodeContext:
    stage: StageName
    codebase_path: str
    repository: NodeRepository
    capabilities: Mapping[str, object]
    prompts: NodePromptRunner
    codegraphs: NodeCodeGraphs
    runtime: NodeRuntime
    callbacks: NodeCallbacks
    triage: TriageAdjudicator | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "capabilities",
            MappingProxyType(dict(self.capabilities)),
        )


@dataclass(frozen=True, slots=True)
class NodeInvocation:
    configuration: BaseModel
    inputs: Mapping[str, object]
    context: NodeContext
    formats: tuple[ResultFormat, ...] | None = None
    filename: str | None = None


@dataclass(frozen=True, slots=True)
class NodeResult:
    outputs: Mapping[str, object]
    status: ExecutionStatus = ExecutionStatus.OK
    diagnostics: tuple[ExecutionDiagnostic, ...] = ()


@dataclass(frozen=True, slots=True)
class NodeRegistration:
    name: str
    stage: StageName
    configuration: type[BaseModel]
    inputs: Mapping[str, Any]
    outputs: Mapping[str, Any]
    execute: NodeHandler
    capabilities: Mapping[str, CapabilityRequirement] = field(default_factory=dict)
    api_version: int | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Execution node name must not be empty")
        if not self.name.isidentifier():
            raise ValueError(f"Execution node name {self.name!r} must be an identifier")
        if self.stage not in STAGE_NAMES:
            raise ValueError(f"Unknown execution stage: {self.stage!r}")
        if not isinstance(self.configuration, type) or not issubclass(
            self.configuration, BaseModel
        ):
            raise TypeError("Execution node configuration must be a Pydantic model")
        if not callable(self.execute):
            raise TypeError(f"Execution node {self.name!r} handler is not callable")
        if (
            self.api_version is not None
            and self.api_version != EXECUTION_NODE_API_VERSION
        ):
            raise ValueError(
                f"Execution node {self.name!r} targets unsupported API version "
                f"{self.api_version}; expected {EXECUTION_NODE_API_VERSION}"
            )
        for port in (*self.inputs, *self.outputs):
            if not port.isidentifier():
                raise ValueError(
                    f"Execution node {self.name!r} has invalid port {port!r}"
                )
        for capability, requirement in self.capabilities.items():
            if not capability.isidentifier():
                raise ValueError(
                    f"Execution node {self.name!r} has invalid capability "
                    f"{capability!r}"
                )
            if not isinstance(requirement, CapabilityRequirement):
                raise TypeError(
                    f"Execution node {self.name!r} capability {capability!r} has "
                    f"invalid requirement {requirement!r}"
                )
        object.__setattr__(self, "inputs", MappingProxyType(dict(self.inputs)))
        object.__setattr__(self, "outputs", MappingProxyType(dict(self.outputs)))
        object.__setattr__(
            self,
            "capabilities",
            MappingProxyType(dict(self.capabilities)),
        )
