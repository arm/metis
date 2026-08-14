# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from typing import Any
from typing import ClassVar

from rich.markup import escape
from rich.progress import Progress


class ReviewCodeProgressReporter:
    _EVENT_HANDLERS: ClassVar[dict[str, str]] = {
        "review_files_start": "_review_files_start",
        "review_result": "_review_result",
        "codegraph_start": "_graph_start",
        "codegraph_progress": "_graph_progress",
        "codegraph_done": "_graph_done",
        "reachability_frontier_review_start": "_frontier_review_start",
        "reachability_frontier_review_done": "_frontier_review_done",
        "findings_finalization_start": "_findings_finalization_start",
        "findings_finalization_progress": "_findings_finalization_progress",
        "findings_finalization_done": "_findings_finalization_done",
        "reachability_code_review_done": "_code_review_done",
    }

    def __init__(self, progress: Progress, *, total_files: int):
        self._progress = progress
        self._total_files = max(int(total_files or 0), 0)
        self._task = progress.add_task(
            "[cyan]Preparing codebase review...[/cyan]",
            total=None,
        )
        self._review_completed = 0
        self._saw_reachability = False
        self._collecting_reachability_results = False
        self._finalizing_review_results = False

    def __call__(self, event: Mapping[str, Any] | None):
        event = event or {}
        kind = str(event.get("event") or "")
        if kind.startswith("execution_"):
            self._generic_event(kind)
            return
        if kind and kind not in {"review_files_start", "review_result"}:
            self._saw_reachability = True

        handler_name = self._EVENT_HANDLERS.get(kind)
        if handler_name is not None:
            getattr(self, handler_name)(event)
            return
        self._generic_event(kind)

    def _review_files_start(self, event: Mapping[str, Any]):
        self._total_files = _non_negative_int(event.get("total")) or 0
        self._progress.update(
            self._task,
            total=self._total_files or None,
            completed=0,
            description="[cyan]Reviewing codebase...[/cyan]",
        )

    def _review_result(self, _event: Mapping[str, Any]):
        self.review_result()

    def review_result(self):
        self._review_completed += 1
        if self._saw_reachability:
            self._reachability_result()
            return

        total = self._total_files or self._review_completed
        completed = min(self._review_completed, total)
        if completed >= total:
            self._finalize_review_results()
            return
        self._progress.update(
            self._task,
            total=total,
            completed=completed,
            description=(
                "[cyan]Collecting review results "
                f"{self._review_completed}/{total}[/cyan]"
            ),
        )

    def finish(self):
        self._replace_task(
            "[green]Review complete[/green]",
            total=1,
            completed=1,
        )

    def _graph_start(self, event: Mapping[str, Any]):
        self._start_phase(
            "[cyan]Building CodeGraph...[/cyan]",
            total=_positive_int(event.get("total")),
        )

    def _graph_progress(self, event: Mapping[str, Any]):
        self._update_progress(
            total=_positive_int(event.get("total")),
            completed=_positive_int(event.get("completed")) or 0,
            description="[cyan]Building CodeGraph[/cyan]",
            final_description="[cyan]Finalizing CodeGraph...[/cyan]",
        )

    def _graph_done(self, event: Mapping[str, Any]):
        self._start_phase(
            (
                "[cyan]CodeGraph ready: "
                f"{event.get('nodes', 0)} functions, "
                f"{event.get('edges', 0)} calls[/cyan]"
            ),
        )

    def _frontier_review_start(self, event: Mapping[str, Any]):
        self._start_phase(
            (
                "[cyan]Reviewing reachability evidence: "
                f"{event.get('nodes', 0)} functions, "
                f"{event.get('edges', 0)} calls[/cyan]"
            ),
            total=_positive_int(event.get("frontiers")),
        )

    def _frontier_review_done(self, event: Mapping[str, Any]):
        failed_nodes = _non_negative_int(event.get("failed_nodes")) or 0
        incomplete_nodes = (
            _non_negative_int(event.get("evidence_incomplete_nodes")) or 0
        )
        self._start_phase(
            (
                "[cyan]Reachability review complete: "
                f"{event.get('reviewed_nodes', 0)}/"
                f"{event.get('planned_nodes', 0)} functions, "
                f"{event.get('findings', 0)} findings, "
                f"functions with review failures: {failed_nodes}, "
                f"functions with incomplete evidence: {incomplete_nodes}[/cyan]"
            ),
        )

    def _findings_finalization_start(self, event: Mapping[str, Any]):
        candidates = event.get("candidates", 0)
        self._start_phase(
            "[cyan]Checking findings for duplicates[/cyan]",
            print_message=(
                f"[cyan]Checking {candidates} findings for duplicates[/cyan]"
            ),
        )

    def _findings_finalization_progress(self, event: Mapping[str, Any]):
        total = _positive_int(event.get("total"))
        completed = _non_negative_int(event.get("completed")) or 0
        phase = str(event.get("phase") or "")
        description = (
            "[cyan]Comparing possible duplicates[/cyan]"
            if phase == "representative"
            else "[cyan]Checking findings for duplicates[/cyan]"
        )
        if total is None:
            self._progress.update(self._task, description=description)
            return
        self._progress.update(
            self._task,
            total=total,
            completed=min(completed, total),
            description=description,
        )

    def _findings_finalization_done(self, event: Mapping[str, Any]):
        self._start_phase(
            (
                "[cyan]Final findings ready: "
                f"{event.get('deduped_findings', 0)} kept, "
                f"{event.get('removed_findings', 0)} removed from "
                f"{event.get('raw_findings', 0)} candidates[/cyan]"
            ),
        )

    def _code_review_done(self, event: Mapping[str, Any]):
        self._start_phase(
            (
                "[cyan]Reachability review output ready: "
                f"{event.get('findings', 0)} findings across "
                f"{event.get('files', 0)} files[/cyan]"
            ),
        )

    def _generic_event(self, kind: str):
        if kind.endswith("_start"):
            self._start_phase(
                f"[cyan]Running {_progress_event_label(kind)}...[/cyan]",
            )
        elif kind.endswith("_done"):
            self._start_phase(
                f"[cyan]Finished {_progress_event_label(kind)}[/cyan]",
            )

    def _reachability_result(self):
        description = (
            "[cyan]Collecting reachability results "
            f"{self._review_completed} files[/cyan]"
        )
        if not self._collecting_reachability_results:
            self._collecting_reachability_results = True
            self._start_phase(description)
            return
        self._progress.update(self._task, description=description)

    def _finalize_review_results(self):
        description = "[cyan]Finalizing review results...[/cyan]"
        if self._finalizing_review_results:
            self._progress.update(self._task, description=description)
            return
        self._finalizing_review_results = True
        self._start_phase(description)

    def _print_phase(self, message: str):
        console = getattr(self._progress, "console", None)
        if console is not None:
            console.print(message)

    def _replace_task(self, description: str, *, total=None, completed=0):
        self._progress.remove_task(self._task)
        self._task = self._progress.add_task(
            description,
            total=total,
            completed=completed,
        )

    def _start_phase(self, description: str, *, total=None, print_message=None):
        self._print_phase(print_message or description)
        self._replace_task(description, total=total, completed=0)

    def _update_progress(
        self,
        *,
        total,
        completed: int,
        description: str,
        final_description: str,
    ):
        total = total or 1
        completed = completed or 0
        if completed >= total:
            self._start_phase(final_description)
            return
        self._progress.update(
            self._task,
            total=total,
            completed=completed,
            description=description,
        )


def _positive_int(value):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _non_negative_int(value):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _progress_event_label(event_name):
    text = str(event_name or "")
    for suffix in ("_start", "_done"):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
    return escape(text.replace("_", " "))
