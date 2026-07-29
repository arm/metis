# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Generic
from typing import Literal
from typing import Protocol
from typing import TypeVar

from pydantic import BaseModel
from pydantic import ConfigDict


class SchemaReference(BaseModel):
    id: str
    version: str

    model_config = ConfigDict(extra="forbid", frozen=True)


class CapabilityReference(BaseModel):
    id: str
    version: str

    model_config = ConfigDict(extra="forbid", frozen=True)


class InputPortManifest(BaseModel):
    name: str
    schema_ref: SchemaReference
    required: bool = True
    description: str = ""

    model_config = ConfigDict(extra="forbid", frozen=True)


class OutputPortManifest(BaseModel):
    name: str
    schema_ref: SchemaReference
    description: str = ""

    model_config = ConfigDict(extra="forbid", frozen=True)


class NodeManifest(BaseModel):
    schema_version: Literal[1]
    node_type: str
    node_version: str
    implementation: str
    input_ports: tuple[InputPortManifest, ...]
    output_ports: tuple[OutputPortManifest, ...]
    config_schema: SchemaReference
    required_resources: tuple[CapabilityReference, ...] = ()
    required_tools: tuple[CapabilityReference, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True, slots=True)
class GraphRunIdentity:
    graph_id: str
    run_id: str


@dataclass(frozen=True, slots=True)
class NodeIdentity:
    instance_id: str
    node_type: str
    node_version: str


@dataclass(frozen=True, slots=True)
class NodeInvocation:
    graph_run: GraphRunIdentity
    node: NodeIdentity
    input_hash: str
    config_hash: str


InputT = TypeVar("InputT")
OutputT = TypeVar("OutputT")
InputT_contra = TypeVar("InputT_contra", contravariant=True)
OutputT_co = TypeVar("OutputT_co", covariant=True)


@dataclass(frozen=True, slots=True)
class NodeRequest(Generic[InputT]):
    invocation: NodeInvocation
    inputs: InputT
    configuration: BaseModel


@dataclass(frozen=True, slots=True)
class NodeContext:
    invocation: NodeInvocation


class NodeStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class NodeDiagnostic:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class OutputProvenance:
    port: str
    source_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class NodeResult(Generic[OutputT]):
    invocation: NodeInvocation
    status: NodeStatus
    output: OutputT | None
    diagnostics: tuple[NodeDiagnostic, ...] = ()
    provenance: tuple[OutputProvenance, ...] = ()


class ExecutionNode(Protocol[InputT_contra, OutputT_co]):
    def __call__(
        self,
        request: NodeRequest[InputT_contra],
        context: NodeContext,
        /,
    ) -> NodeResult[OutputT_co]: ...
