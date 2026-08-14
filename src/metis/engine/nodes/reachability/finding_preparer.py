# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from metis.engine.nodes.codegraph.annotations import normalize_sink_type
from metis.engine.nodes.reachability.options import DEFAULT_REACHABILITY_MAX_PATH_LENGTH

from .finding_paths import FindingPathAnnotator
from .graph_utils import _same_file


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


def prepare_findings(
    findings,
    graph,
    *,
    max_path_length=DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
    target_file="",
):
    if target_file:
        findings = FindingPathAnnotator(
            graph,
            target_file,
            max_path_length=max_path_length,
        ).annotate(findings)
    else:
        findings = annotate_findings_with_source_paths(
            findings,
            graph,
            max_path_length=max_path_length,
        )
    for finding in findings:
        finding.vulnerability_type = normalize_sink_type(
            getattr(finding, "vulnerability_type", "")
        )
    return findings


def annotate_findings_with_source_paths(
    findings,
    graph,
    *,
    max_path_length=DEFAULT_REACHABILITY_MAX_PATH_LENGTH,
):
    annotated = []
    annotators = {}
    for finding in findings:
        target_file = finding.primary_file or finding.sink_file or finding.source_file
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
