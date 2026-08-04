# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

import metis.execution_nodes as execution_nodes
from metis.engine.execution.catalog import NodeCatalog


class _UnversionedEntryPoint:
    name = "review.private_node"

    @staticmethod
    def load() -> execution_nodes.NodeRegistration:
        return execution_nodes.NodeRegistration(
            name="private_node",
            stage="review",
            configuration=execution_nodes.EmptyNodeConfiguration,
            inputs={},
            outputs={},
            execute=lambda _invocation: execution_nodes.NodeResult({}),
        )


def test_execution_node_public_api_is_explicit() -> None:
    assert set(execution_nodes.__all__) == {
        "CapabilityRequirement",
        "CodeGraph",
        "CodeGraphProvider",
        "CodeGraphProviderContext",
        "CodeGraphReference",
        "CodeGraphResult",
        "EmptyNodeConfiguration",
        "EXECUTION_NODE_API_VERSION",
        "ExecutionDiagnostic",
        "ExecutionStatus",
        "NodeCallbacks",
        "NodeCodeGraphs",
        "NodeContext",
        "NodeInvocation",
        "NodeRegistration",
        "NodeResult",
        "NodeRuntime",
        "PatchReviewResult",
        "ReviewCommand",
        "ReviewResult",
        "ReviewRun",
        "ReviewStatus",
        "SarifFinding",
        "SarifPayload",
        "StandardReviewResult",
        "TriageAdjudicator",
        "TriageClassifier",
        "TriageDecision",
        "TriageRun",
    }


def test_execution_node_registration_rejects_an_unsupported_api_version() -> None:
    with pytest.raises(ValueError, match="unsupported API version 2; expected 1"):
        execution_nodes.NodeRegistration(
            name="private_node",
            stage="review",
            configuration=execution_nodes.EmptyNodeConfiguration,
            inputs={},
            outputs={},
            execute=lambda _invocation: execution_nodes.NodeResult({}),
            api_version=2,
        )


def test_installed_execution_node_must_declare_its_api_version() -> None:
    catalog = NodeCatalog((), (_UnversionedEntryPoint(),))

    with pytest.raises(ValueError, match="must declare api_version"):
        catalog.resolve("review", "private_node")
