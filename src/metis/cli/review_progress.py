# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from typing import Any

from rich.markup import escape
from rich.progress import Progress


class ReviewCodeProgressReporter:
    _EVENT_HANDLERS = {
        "treesitter_graph_start": "_graph_start",
        "treesitter_graph_progress": "_graph_progress",
        "treesitter_graph_done": "_graph_done",
        "treesitter_paths_done": "_paths_done",
        "intra_audit_start": "_intra_audit_start",
        "intra_audit_progress": "_intra_audit_progress",
        "confirmation_start": "_confirmation_start",
        "confirmation_progress": "_confirmation_progress",
        "confirmation_done": "_confirmation_done",
        "supplementary_done": "_supplementary_done",
        "findings_finalization_start": "_findings_finalization_start",
        "findings_finalization_progress": "_findings_finalization_progress",
        "findings_finalization_done": "_findings_finalization_done",
        "treesitter_code_review_done": "_code_review_done",
        "review_output_aggregation_start": "_review_output_aggregation_start",
        "review_output_aggregation_done": "_review_output_aggregation_done",
    }

    def __init__(self, progress: Progress, *, total_files: int):
        self._progress = progress
        self._total_files = max(int(total_files or 0), 0)
        self._task = progress.add_task(
            "[cyan]Preparing codebase review...[/cyan]",
            total=None,
        )
        self._review_completed = 0
        self._confirmation_pending = False
        self._saw_reachability = False
        self._collecting_reachability_results = False
        self._reachability_result_total = 0

    def __call__(self, event: Mapping[str, Any] | None):
        event = event or {}
        kind = str(event.get("event") or "")
        if kind:
            self._saw_reachability = True

        handler_name = self._EVENT_HANDLERS.get(kind)
        if handler_name is not None:
            getattr(self, handler_name)(event)
            return
        self._generic_event(kind)

    def review_result(self):
        self._review_completed += 1
        if self._saw_reachability:
            self._reachability_result()
            return

        total = self._total_files or self._review_completed
        completed = min(self._review_completed, total)
        if completed >= total:
            self._start_phase("[cyan]Finalizing review results...[/cyan]")
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
            "[cyan]Building reachability graph...[/cyan]",
            total=_positive_int(event.get("total")),
        )

    def _graph_progress(self, event: Mapping[str, Any]):
        self._update_progress(
            total=_positive_int(event.get("total")),
            completed=_positive_int(event.get("completed")) or 0,
            description="[cyan]Building reachability graph[/cyan]",
            final_description="[cyan]Finalizing reachability graph...[/cyan]",
        )

    def _graph_done(self, event: Mapping[str, Any]):
        self._start_phase(
            (
                "[cyan]Reachability graph ready; finding paths "
                f"{event.get('nodes', 0)} functions, "
                f"{event.get('edges', 0)} calls[/cyan]"
            ),
        )

    def _paths_done(self, event: Mapping[str, Any]):
        selected = _positive_int(event.get("selected")) or 0
        self._confirmation_pending = bool(
            event.get("confirmation_enabled") and selected
        )
        self._start_phase(
            (
                "[cyan]Reachability paths ready; running lenses "
                f"{event.get('paths', 0)} paths, "
                f"{event.get('selected', 0)} selected[/cyan]"
            ),
        )

    def _intra_audit_start(self, event: Mapping[str, Any]):
        self._start_phase(
            "[cyan]Running intra-file reachability audit...[/cyan]",
            total=_positive_int(event.get("files")),
        )

    def _intra_audit_progress(self, event: Mapping[str, Any]):
        self._update_progress(
            total=_positive_int(event.get("total")),
            completed=_positive_int(event.get("completed")) or 0,
            description="[cyan]Auditing reachability files[/cyan]",
            final_description="[cyan]Finalizing intra-file audit...[/cyan]",
        )

    def _confirmation_start(self, event: Mapping[str, Any]):
        self._start_phase(
            "[cyan]Confirming reachable paths...[/cyan]",
            total=_positive_int(event.get("total")),
        )

    def _confirmation_progress(self, event: Mapping[str, Any]):
        self._update_progress(
            total=_positive_int(event.get("total")),
            completed=_positive_int(event.get("completed")) or 0,
            description="[cyan]Confirming reachable paths...[/cyan]",
            final_description="[cyan]Finalizing path confirmation...[/cyan]",
        )

    def _confirmation_done(self, event: Mapping[str, Any]):
        self._confirmation_pending = False
        self._start_phase(
            (
                "[cyan]Path confirmation complete: "
                f"{event.get('confirmed', 0)} candidate findings[/cyan]"
            ),
        )

    def _supplementary_done(self, event: Mapping[str, Any]):
        next_phase = "; confirming selected paths" if self._confirmation_pending else ""
        self._start_phase(
            (
                "[cyan]Reachability lenses complete: "
                f"{event.get('total', 0)} candidate findings{next_phase}[/cyan]"
            ),
        )

    def _findings_finalization_start(self, event: Mapping[str, Any]):
        candidates = event.get("candidates", 0)
        supplementary = event.get("supplementary_findings")
        path_findings = event.get("path_findings")
        source_breakdown = (
            f" ({supplementary} lenses, {path_findings} paths)"
            if supplementary is not None and path_findings is not None
            else ""
        )
        self._start_phase(
            "[cyan]Deduplicating findings[/cyan]",
            print_message=(
                "[cyan]Going through "
                f"{candidates} candidate findings{source_breakdown}[/cyan]"
            ),
        )

    def _findings_finalization_progress(self, event: Mapping[str, Any]):
        self._progress.update(
            self._task,
            description="[cyan]Adjudicating final findings[/cyan]",
        )

    def _findings_finalization_done(self, event: Mapping[str, Any]):
        self._start_phase(
            (
                "[cyan]Final findings ready: "
                f"{event.get('deduped_findings', 0)} kept, "
                f"{event.get('removed_findings', 0)} removed from "
                f"{event.get('raw_findings', 0)} candidates; grouping by file[/cyan]"
            ),
        )

    def _code_review_done(self, event: Mapping[str, Any]):
        self._start_phase(
            (
                "[cyan]Reachability review output ready: "
                f"{event.get('deduped_findings', 0)} findings across "
                f"{event.get('files', 0)} files[/cyan]"
            ),
        )

    def _review_output_aggregation_start(self, event: Mapping[str, Any]):
        self._start_phase("[cyan]Finalizing reachability output...[/cyan]")

    def _review_output_aggregation_done(self, event: Mapping[str, Any]):
        total = _positive_int(event.get("files")) or 0
        self._reachability_result_total = total
        self._start_phase(
            "[cyan]Collecting reachability results[/cyan]",
            total=total,
            print_message=(
                "[cyan]Reachability output finalized; collecting "
                f"{total} file results[/cyan]"
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
        if self._reachability_result_total:
            completed = min(self._review_completed, self._reachability_result_total)
            if completed >= self._reachability_result_total:
                self._start_phase("[cyan]Finalizing review results...[/cyan]")
                return
            self._progress.update(
                self._task,
                total=self._reachability_result_total,
                completed=completed,
                description="[cyan]Collecting reachability results[/cyan]",
            )
            return

        description = (
            "[cyan]Collecting reachability results "
            f"{self._review_completed} files[/cyan]"
        )
        if not self._collecting_reachability_results:
            self._collecting_reachability_results = True
            self._start_phase(description)
            return
        self._progress.update(self._task, description=description)

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


def _progress_event_label(event_name):
    text = str(event_name or "")
    for suffix in ("_start", "_done"):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
    return escape(text.replace("_", " "))
