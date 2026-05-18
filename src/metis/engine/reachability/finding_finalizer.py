# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Finding path annotation, filtering, and deduplication."""

from __future__ import annotations

from metis.reachability_settings import DEFAULT_REACHABILITY_MAX_PATH_LENGTH

from .dedup import Deduplicator
from .finding_paths import FindingPathAnnotator
from .graph_utils import _same_file
from .post_filters import _post_filter_findings, _strict_file_findings


class FindingFinalizer:
    """Prepare reachability findings for review output."""

    def __init__(self, codebase_path: str):
        self._codebase_path = codebase_path

    def finalize(
        self,
        findings,
        graph,
        *,
        max_paths_per_sink,
        max_path_length=DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
        target_file="",
        strict_file=False,
    ):
        if target_file:
            findings = FindingPathAnnotator(
                graph,
                target_file,
                max_path_length=max_path_length,
            ).annotate(findings)
            if strict_file:
                findings = _strict_file_findings(findings)
        else:
            findings = self.annotate_findings_with_source_paths(
                findings,
                graph,
                max_path_length=max_path_length,
            )

        findings = _post_filter_findings(findings, self._codebase_path)
        if not findings:
            return [], 0, 0
        return Deduplicator.deduplicate(findings, max_per_sink=max_paths_per_sink)

    def annotate_findings_with_source_paths(
        self,
        findings,
        graph,
        *,
        max_path_length=DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
    ):
        annotated = []
        annotators = {}
        for finding in findings:
            target_file = (
                finding.primary_file or finding.sink_file or finding.source_file
            )
            if not target_file:
                annotated.append(finding)
                continue
            annotator = annotators.get(target_file)
            if annotator is None:
                annotator = FindingPathAnnotator(
                    graph,
                    target_file,
                    max_path_length=max_path_length,
                )
                annotators[target_file] = annotator
            annotated.append(annotator.annotate_one(finding))
        return annotated

    @staticmethod
    def participates_in_file(finding, target_file, graph):
        if any(
            _same_file(file_name, target_file)
            for file_name in (
                finding.primary_file,
                finding.source_file,
                finding.sink_file,
            )
        ):
            return True
        for node_name in list(finding.path or []) + [
            finding.primary_function,
            finding.source_function,
            finding.sink_function,
        ]:
            node = graph.get_node(node_name) if graph is not None else None
            if node and _same_file(node.file_path, target_file):
                return True
            if str(node_name or "").startswith(f"{target_file}::"):
                return True
        return False
