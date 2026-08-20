# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import metis.execution_nodes as execution_nodes


def test_execution_node_public_api_is_explicit() -> None:
    assert set(execution_nodes.__all__) == {
        "CapabilityRequirement",
        "CodeGraph",
        "CodeGraphProvider",
        "CodeGraphProviderContext",
        "CodeGraphReference",
        "CodeGraphResult",
        "EmptyNodeConfiguration",
        "ExecutionDiagnostic",
        "ExecutionStatus",
        "NodeCallbacks",
        "NodeCodeGraphs",
        "NodeContext",
        "NodeInvocation",
        "NodeJobs",
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
