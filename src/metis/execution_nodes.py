# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Public Execution Node API for separately distributed nodes.

The exported names are contracts used to register and implement nodes. They are
not executable nodes or names that can be selected in YAML. A node becomes
selectable only through a stage-qualified :class:`NodeRegistration` supplied by
Metis or an installed package.
"""

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphProvider
from metis.engine.codegraph import CodeGraphProviderContext
from metis.engine.codegraph import CodeGraphReference
from metis.engine.codegraph import CodeGraphResult
from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import EXECUTION_NODE_API_VERSION
from metis.engine.execution.contracts import CapabilityRequirement
from metis.engine.execution.contracts import ExecutionDiagnostic
from metis.engine.execution.contracts import ExecutionStatus
from metis.engine.execution.contracts import NodeContext
from metis.engine.execution.contracts import NodeCodeGraphs
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.execution.contracts import NodeRuntime
from metis.engine.execution.contracts import NodeCallbacks
from metis.engine.stages.review.models import PatchReviewResult
from metis.engine.stages.review.models import ReviewCommand
from metis.engine.stages.review.models import ReviewResult
from metis.engine.stages.review.models import ReviewRun
from metis.engine.stages.review.models import ReviewStatus
from metis.engine.stages.review.models import StandardReviewResult
from metis.engine.stages.triage.contracts import TriageAdjudicator
from metis.engine.stages.triage.contracts import TriageClassifier
from metis.engine.stages.triage.contracts import TriageDecision
from metis.engine.stages.triage.models import TriageRun
from metis.sarif.triage import SarifFinding
from metis.sarif.models import SarifPayload

__all__ = [
    "CodeGraph",
    "CodeGraphProvider",
    "CodeGraphProviderContext",
    "CodeGraphReference",
    "CodeGraphResult",
    "CapabilityRequirement",
    "EmptyNodeConfiguration",
    "EXECUTION_NODE_API_VERSION",
    "ExecutionDiagnostic",
    "ExecutionStatus",
    "NodeContext",
    "NodeCodeGraphs",
    "NodeInvocation",
    "NodeRegistration",
    "NodeResult",
    "NodeRuntime",
    "NodeCallbacks",
    "PatchReviewResult",
    "ReviewCommand",
    "ReviewResult",
    "ReviewRun",
    "ReviewStatus",
    "SarifPayload",
    "StandardReviewResult",
    "SarifFinding",
    "TriageAdjudicator",
    "TriageClassifier",
    "TriageDecision",
    "TriageRun",
]
