# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Shared reachability graph, finding, and analysis helpers."""

from __future__ import annotations

from .dedup import Deduplicator
from .confirmer import VulnerabilityConfirmer
from .models import (
    FunctionNode,
    GlobalConstruct,
    ReachabilityGraph,
    ReachabilityPath,
    VulnerabilityFinding,
)
from .supplementary import SupplementaryAnalyzer
from .tracing import (
    SourceRootedPathTracer,
)

__all__ = [
    "Deduplicator",
    "FunctionNode",
    "GlobalConstruct",
    "ReachabilityGraph",
    "ReachabilityPath",
    "SourceRootedPathTracer",
    "SupplementaryAnalyzer",
    "VulnerabilityConfirmer",
    "VulnerabilityFinding",
]
