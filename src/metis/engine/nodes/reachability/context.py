# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import threading
from collections.abc import Callable

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.nodes.codegraph import CodeGraphService
from metis.engine.nodes.reachability.options import DEFAULT_REACHABILITY_MAX_PATH_LENGTH

from .domain import ReachabilityPath
from .graph_utils import graph_fingerprint
from .options import ReachabilityReviewOptions
from .tracing import SourceRootedPathTracer


class ReachabilityContext:
    def __init__(self, codegraphs: CodeGraphService) -> None:
        self._codegraphs = codegraphs
        self._paths: dict[tuple[str, int], list[ReachabilityPath]] = {}
        self._lock = threading.RLock()

    def graph(
        self,
        *,
        options: ReachabilityReviewOptions,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
    ) -> CodeGraph:
        selected = self._codegraphs.materialize(
            progress_callback=options.progress_callback,
            diagnostic_callback=diagnostic_callback,
        )
        return self._codegraphs.load(selected)

    def graph_and_paths(
        self,
        *,
        options: ReachabilityReviewOptions,
        codegraph: CodeGraph | None = None,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
    ) -> tuple[CodeGraph, list[ReachabilityPath]]:
        graph = codegraph or self.graph(
            options=options,
            diagnostic_callback=diagnostic_callback,
        )
        max_path_length = int(
            options.max_path_length or DEFAULT_REACHABILITY_MAX_PATH_LENGTH
        )
        key = (graph_fingerprint(graph), max_path_length)
        with self._lock:
            cached = self._paths.get(key)
            if cached is not None:
                return graph, list(cached)
        paths = SourceRootedPathTracer(
            graph,
            max_path_length=max_path_length,
            max_workers=options.max_workers,
            progress_callback=options.progress_callback,
        ).find_all_paths()
        with self._lock:
            stored = self._paths.setdefault(key, list(paths))
        return graph, list(stored)

    def supports_file(self, path: str) -> bool:
        return self._codegraphs.supports_file(
            path
        ) and self._codegraphs.supports_semantics(path)
