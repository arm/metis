# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from typing import Protocol
from typing_extensions import NotRequired
from typing_extensions import Required
from typing_extensions import TypedDict

from metis.engine.execution.contracts import CheckpointCallback
from metis.engine.execution.contracts import DebugCallback
from metis.engine.execution.contracts import NodeJobs
from metis.engine.execution.contracts import ProgressCallback
from metis.sarif.triage import SarifFinding
from metis.memory import MemoryService

from .models import TriageRun


class TriageDecision(TypedDict):
    status: Required[str]
    reason: Required[str]
    evidence_obligations: NotRequired[list[str]]
    evidence_coverage: NotRequired[dict[str, int]]
    missing_evidence: NotRequired[list[str]]
    threat_model_policy: NotRequired[dict[str, Any]]


TriageClassifier = Callable[
    [SarifFinding, list[dict[str, Any]], DebugCallback | None],
    TriageDecision | None,
]


class TriageAdjudicator(Protocol):
    def triage_run(
        self,
        run: TriageRun,
        *,
        classifier: TriageClassifier,
        jobs: NodeJobs,
        memory_service: MemoryService | None = None,
        progress_callback: ProgressCallback | None = None,
        debug_callback: DebugCallback | None = None,
        checkpoint_callback: CheckpointCallback | None = None,
    ) -> TriageRun: ...
