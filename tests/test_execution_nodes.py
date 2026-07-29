# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import ValidationError

from metis.engine.execution import GraphRunIdentity
from metis.engine.execution import NodeContext
from metis.engine.execution import NodeIdentity
from metis.engine.execution import NodeInvocation
from metis.engine.execution import NodeManifest
from metis.engine.execution import NodeRequest
from metis.engine.execution import NodeResult
from metis.engine.execution import NodeStatus
from metis.engine.execution import load_execution_node


class AnalysisInputs(BaseModel):
    source: str
    guidance: str | None = None

    model_config = ConfigDict(extra="forbid")


class AnalysisOutput(BaseModel):
    finding: str

    model_config = ConfigDict(extra="forbid")


class InitializationOutput(BaseModel):
    initialized: bool

    model_config = ConfigDict(extra="forbid")


class EmptyModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RepositoryReader:
    def __init__(self, content: str):
        self.content = content

    def read(self) -> str:
        return self.content


class ReviewService:
    def review(self, source: str) -> str:
        return f"reviewed: {source}"


@dataclass(frozen=True, slots=True)
class RepositoryContext(NodeContext):
    repository: RepositoryReader


@dataclass(frozen=True, slots=True)
class ReviewContext(NodeContext):
    review_service: ReviewService


def initialize_node(
    request: NodeRequest[EmptyModel],
    context: NodeContext,
) -> NodeResult[InitializationOutput]:
    assert request.invocation == context.invocation
    return NodeResult(
        invocation=request.invocation,
        status=NodeStatus.SUCCEEDED,
        output=InitializationOutput(initialized=True),
    )


class DeterministicAnalysis:
    def __call__(
        self,
        request: NodeRequest[AnalysisInputs],
        context: NodeContext,
    ) -> NodeResult[AnalysisOutput]:
        assert isinstance(context, RepositoryContext)
        assert request.inputs.guidance is None
        assert not hasattr(context, "review_service")
        return _successful_result(
            request,
            f"{request.inputs.source}: {context.repository.read()}",
        )


def review_service_node(
    request: NodeRequest[AnalysisInputs],
    context: NodeContext,
) -> NodeResult[AnalysisOutput]:
    assert isinstance(context, ReviewContext)
    assert not hasattr(context, "repository")
    return _successful_result(
        request,
        context.review_service.review(request.inputs.source),
    )


def _successful_result(
    request: NodeRequest[AnalysisInputs],
    finding: str,
) -> NodeResult[AnalysisOutput]:
    return NodeResult(
        invocation=request.invocation,
        status=NodeStatus.SUCCEEDED,
        output=AnalysisOutput(finding=finding),
    )


def _manifest() -> NodeManifest:
    return NodeManifest.model_validate(
        {
            "schema_version": 1,
            "node_type": "fixture.analysis",
            "node_version": "1",
            "implementation": "fixture_nodes:node",
            "input_ports": [
                {
                    "name": "source",
                    "schema_ref": {"id": "source", "version": "1"},
                },
                {
                    "name": "guidance",
                    "schema_ref": {"id": "guidance", "version": "1"},
                    "required": False,
                },
            ],
            "output_ports": [
                {
                    "name": "finding",
                    "schema_ref": {"id": "finding", "version": "1"},
                }
            ],
            "config_schema": {"id": "fixture-config", "version": "1"},
        }
    )


def _invocation() -> NodeInvocation:
    return NodeInvocation(
        graph_run=GraphRunIdentity(graph_id="fixture", run_id="run-1"),
        node=NodeIdentity(
            instance_id="analysis",
            node_type="fixture.analysis",
            node_version="1",
        ),
        input_hash="input-hash",
        config_hash="config-hash",
    )


def _analysis_request() -> NodeRequest[AnalysisInputs]:
    return NodeRequest(
        invocation=_invocation(),
        inputs=AnalysisInputs(source="unsafe()"),
        configuration=EmptyModel(),
    )


def test_manifest_preserves_authored_identifier_and_requiredness():
    data = _manifest().model_dump(mode="json")
    data["node_type"] = " review node / α "

    manifest = NodeManifest.model_validate(data)

    assert manifest.node_type == " review node / α "
    assert manifest.input_ports[0].required is True


def test_manifest_rejects_unsupported_schema_version():
    data = _manifest().model_dump(mode="json")
    data["schema_version"] = 2

    with pytest.raises(ValidationError):
        NodeManifest.model_validate(data)


def test_implementation_import_is_explicit_and_lazy(monkeypatch):
    imports = []
    implementation = DeterministicAnalysis()

    def load_fixture(name):
        imports.append(name)
        return SimpleNamespace(node=implementation)

    monkeypatch.setattr(
        "metis.engine.execution.loading.importlib.import_module",
        load_fixture,
    )
    manifest = _manifest()

    assert imports == []
    node = load_execution_node(manifest)

    assert imports == ["fixture_nodes"]
    assert node is implementation


def test_fixture_nodes_execute_through_the_shared_contract():
    invocation = _invocation()
    initialization = initialize_node(
        NodeRequest(
            invocation=invocation,
            inputs=EmptyModel(),
            configuration=EmptyModel(),
        ),
        NodeContext(invocation=invocation),
    )
    analysis_request = _analysis_request()
    analysis = DeterministicAnalysis()(
        analysis_request,
        RepositoryContext(
            invocation=analysis_request.invocation,
            repository=RepositoryReader("evidence"),
        ),
    )
    review = review_service_node(
        analysis_request,
        ReviewContext(
            invocation=analysis_request.invocation,
            review_service=ReviewService(),
        ),
    )

    assert initialization.output == InitializationOutput(initialized=True)
    assert analysis.output == AnalysisOutput(finding="unsafe(): evidence")
    assert review.output == AnalysisOutput(finding="reviewed: unsafe()")
