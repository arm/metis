# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import os

from .finding_adapter import finding_to_review_item
from .finding_adapter import review_sort_key


def group_findings_as_reviews(findings, *, codebase_path):
    by_file = {}
    for finding in findings:
        primary_file = finding.primary_file or finding.sink_file or finding.source_file
        if primary_file:
            by_file.setdefault(primary_file, []).append(finding)

    reviews = []
    for target_file in sorted(by_file):
        items = reviews_for_findings(
            by_file[target_file],
            codebase_path=codebase_path,
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


def reviews_for_findings(findings, *, codebase_path):
    reviews = [
        finding_to_review_item(finding, codebase_path=codebase_path)
        for finding in findings
    ]
    reviews.sort(key=review_sort_key)
    return reviews
