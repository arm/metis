# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import os

from metis.engine.review_finding_adapter import (
    finding_to_review_item,
    review_sort_key as _review_sort_key,
)


def group_findings_as_reviews(findings, graph, *, codebase_path):
    by_file = {}
    for finding in findings:
        primary_file = finding.primary_file or finding.sink_file or finding.source_file
        if primary_file:
            by_file.setdefault(primary_file, []).append(finding)

    reviews = []
    for target_file in sorted(by_file):
        items = reviews_for_findings(
            by_file[target_file],
            graph,
            codebase_path=codebase_path,
            target_file=target_file,
        )
        if items:
            reviews.append(
                {
                    "file": target_file,
                    "file_path": os.path.join(codebase_path, target_file),
                    "reviews": items,
                }
            )
    return reviews


def reviews_for_findings(findings, graph, *, codebase_path, target_file):
    reviews = [
        finding_to_review(
            finding, graph=graph, codebase_path=codebase_path, target_file=target_file
        )
        for finding in findings
    ]
    reviews.sort(key=review_sort_key)
    return reviews


def review_sort_key(item):
    return _review_sort_key(item)


def finding_to_review(finding, *, graph=None, codebase_path, target_file=""):
    return finding_to_review_item(
        finding,
        graph=graph,
        codebase_path=codebase_path,
        target_file=target_file,
    )
