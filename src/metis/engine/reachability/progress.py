# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


class ReachabilityProgress:
    CONFIGURED_SECURITY_FUNCTIONS_DONE = "configured_security_functions_done"
    CONFIGURED_SOURCE_FUNCTIONS_DONE = "configured_source_functions_done"
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
    TREESITTER_CODE_REVIEW_DONE = "treesitter_code_review_done"
    TREESITTER_FILE_PATHS_DONE = "treesitter_file_paths_done"
    TREESITTER_FILE_REVIEW_DONE = "treesitter_file_review_done"
    TREESITTER_GRAPH_DONE = "treesitter_graph_done"
    TREESITTER_GRAPH_PROGRESS = "treesitter_graph_progress"
    TREESITTER_GRAPH_START = "treesitter_graph_start"
    TREESITTER_PATHS_DONE = "treesitter_paths_done"
    TREESITTER_PATHS_PROGRESS = "treesitter_paths_progress"
    TREESITTER_PATHS_START = "treesitter_paths_start"


def emit_progress(callback, event, **payload):
    if callback:
        callback({"event": event, **payload})
