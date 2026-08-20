# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


class ReachabilityProgress:
    PHASE_PROGRESS = "reachability_phase_progress"
    FRONTIER_REVIEW_DONE = "reachability_frontier_review_done"
    FRONTIER_REVIEW_START = "reachability_frontier_review_start"
    CODE_REVIEW_DONE = "reachability_code_review_done"
    FILE_REVIEW_DONE = "reachability_file_review_done"


def emit_progress(callback, event, **payload):
    if callback:
        callback({"event": event, **payload})


def emit_phase_progress(callback, phase, completed, total):
    emit_progress(
        callback,
        ReachabilityProgress.PHASE_PROGRESS,
        phase=phase,
        completed=completed,
        total=total,
    )
