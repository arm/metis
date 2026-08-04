# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


class ReachabilityProgress:
    CONFIRMATION_DONE = "confirmation_done"
    CONFIRMATION_PROGRESS = "confirmation_progress"
    CONFIRMATION_START = "confirmation_start"
    FINDINGS_FINALIZATION_DONE = "findings_finalization_done"
    FINDINGS_FINALIZATION_PROGRESS = "findings_finalization_progress"
    FINDINGS_FINALIZATION_START = "findings_finalization_start"
    GLOBAL_LIFECYCLE_DONE = "global_lifecycle_done"
    GLOBAL_LIFECYCLE_START = "global_lifecycle_start"
    INTRA_AUDIT_PROGRESS = "intra_audit_progress"
    INTRA_AUDIT_START = "intra_audit_start"
    LOCK_ORDER_EXTRACTION_DONE = "lock_order_extraction_done"
    LOCK_ORDER_EXTRACTION_START = "lock_order_extraction_start"
    REVIEW_OUTPUT_AGGREGATION_DONE = "review_output_aggregation_done"
    REVIEW_OUTPUT_AGGREGATION_START = "review_output_aggregation_start"
    SUPPLEMENTARY_DONE = "supplementary_done"
    CODE_REVIEW_DONE = "reachability_code_review_done"
    FILE_PATHS_DONE = "reachability_file_paths_done"
    FILE_REVIEW_DONE = "reachability_file_review_done"
    PATHS_DONE = "reachability_paths_done"
    PATHS_PROGRESS = "reachability_paths_progress"
    PATHS_START = "reachability_paths_start"


def emit_progress(callback, event, **payload):
    if callback:
        callback({"event": event, **payload})
