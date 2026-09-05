# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from typing import Any
from typing import ClassVar

from rich.markup import escape
from rich.progress import Progress
from rich.progress import TaskID

from .triage_cli import TriageProgressReporter


class ReviewCodeProgressReporter:
    _NODE_LABELS: ClassVar[dict[str, str]] = {
        "codegraph": "CodeGraph",
        "simple_llm_review": "Simple LLM review",
        "reachability": "Reachability",
        "finding_dedup": "Dedup",
    }
    _REACHABILITY_PHASES: ClassVar[dict[str, tuple[str, str]]] = {
        "scope": ("Preparing reachability scope", "files"),
        "analysis": ("Building reachability analysis", "files"),
        "contracts": ("Deriving reachability contracts", "functions"),
        "evidence": ("Preparing reachability evidence", "files"),
        "packets": ("Reviewing reachability packets", "packets"),
    }
    _EVENT_HANDLERS: ClassVar[dict[str, str]] = {
        "execution_stage_start": "_execution_stage_start",
        "execution_node_start": "_execution_node_start",
        "execution_node_end": "_execution_node_end",
        "review_files_start": "_review_files_start",
        "review_result": "_review_result",
        "codegraph_start": "_graph_start",
        "codegraph_progress": "_graph_progress",
        "codegraph_done": "_graph_done",
        "codegraph_reused": "_graph_reused",
        "reachability_phase_progress": "_reachability_phase_progress",
        "reachability_frontier_review_start": "_frontier_review_start",
        "reachability_frontier_review_done": "_frontier_review_done",
        "findings_finalization_start": "_findings_finalization_start",
        "findings_finalization_progress": "_findings_finalization_progress",
        "findings_finalization_done": "_findings_finalization_done",
        "reachability_code_review_done": "_code_review_done",
    }

    def __init__(self, progress: Progress):
        self._progress = progress
        self._tasks = {
            node: progress.add_task(
                f"[bright_black]○ {label} waiting[/bright_black]",
                total=1,
                completed=0,
            )
            for node, label in self._NODE_LABELS.items()
        }
        self._finished_nodes: set[str] = set()
        self._file_totals = {"simple_llm_review": 0, "reachability": 0}
        self._file_completed = {"simple_llm_review": 0, "reachability": 0}
        self._file_resumed = {"simple_llm_review": 0, "reachability": 0}
        self._node_summaries: dict[str, str] = {}

    def __call__(self, event: Mapping[str, Any] | None):
        event = event or {}
        kind = str(event.get("event") or "")

        handler_name = self._EVENT_HANDLERS.get(kind)
        if handler_name is not None:
            getattr(self, handler_name)(event)

    def _review_files_start(self, event: Mapping[str, Any]):
        node = _review_event_node(event)
        total = _non_negative_int(event.get("total")) or 0
        self._file_totals[node] = total
        self._file_completed[node] = 0
        self._file_resumed[node] = 0
        self._progress.update(
            self._tasks[node],
            total=total or None,
            completed=0,
            description=(
                "[cyan]Reviewing codebase...[/cyan]"
                if node == "simple_llm_review"
                else "[cyan]Reviewing reachability fallback files...[/cyan]"
            ),
        )

    def _review_result(self, event: Mapping[str, Any]):
        node = _review_event_node(event)
        completed = _non_negative_int(event.get("completed"))
        resumed = _non_negative_int(event.get("resumed")) or 0
        current = (
            self._file_completed[node] + 1
            if completed is None
            else max(self._file_completed[node], completed)
        )
        self._file_completed[node] = current
        self._file_resumed[node] = max(self._file_resumed[node], resumed)

        total = self._file_totals[node] or current
        completed = min(current, total)
        if node == "reachability":
            self._progress.update(
                self._tasks[node],
                total=total,
                completed=completed,
                description=(
                    f"[cyan]Reachability fallback complete: {total} files[/cyan]"
                    if completed >= total
                    else (
                        "[cyan]Reviewing reachability fallback "
                        f"{completed}/{total} files[/cyan]"
                    )
                ),
            )
            return
        if completed >= total:
            self._progress.update(
                self._tasks[node],
                total=total,
                completed=completed,
                description=(
                    f"[cyan]Resumed {self._file_resumed[node]}/{total} reviewed "
                    "files; finalizing...[/cyan]"
                    if self._file_resumed[node]
                    else "[cyan]Finalizing review results...[/cyan]"
                ),
            )
            return
        self._progress.update(
            self._tasks[node],
            total=total,
            completed=completed,
            description=(
                (
                    f"[cyan]Resumed {self._file_resumed[node]} files; review progress "
                    f"{current}/{total}[/cyan]"
                )
                if self._file_resumed[node]
                else f"[cyan]Collecting review results {current}/{total}[/cyan]"
            ),
        )

    def _execution_stage_start(self, event: Mapping[str, Any]):
        stage = _stage_progress_label(event.get("stage"))
        self._print_phase(f"[cyan]Stage: {stage}[/cyan]")

    def _execution_node_start(self, event: Mapping[str, Any]):
        node = str(event.get("node") or "")
        label = self._NODE_LABELS.get(node)
        if label is None:
            self._print_phase(_node_start_description(event))
            return
        self._start_phase(node, f"[cyan]{label} running...[/cyan]")

    def _execution_node_end(self, event: Mapping[str, Any]):
        node = str(event.get("node") or "")
        label = self._NODE_LABELS.get(node)
        if label is None:
            self._print_phase(_node_completion_description(event))
            return
        if node in self._finished_nodes:
            return
        status = str(event.get("status") or "")
        if status == "error":
            self._finish_node(node, f"[red]✗ {label} failed[/red]")
            return
        summary = self._node_summaries.get(node, f"{label} complete")
        if status == "inconclusive":
            self._finish_node(node, f"[yellow]! {summary}[/yellow]")
            return
        self._finish_node(node, f"[green]✓ {summary}[/green]")

    def finish(self):
        for node, label in self._NODE_LABELS.items():
            if node not in self._finished_nodes:
                self._finish_node(
                    node,
                    f"[bright_black]○ {label} not run[/bright_black]",
                )

    def remove(self) -> None:
        for task in self._tasks.values():
            self._progress.remove_task(task)

    def _graph_start(self, event: Mapping[str, Any]):
        self._start_phase(
            "codegraph",
            "[cyan]Building CodeGraph...[/cyan]",
            total=_positive_int(event.get("total")),
        )

    def _graph_progress(self, event: Mapping[str, Any]):
        total = _positive_int(event.get("total")) or 1
        completed = _positive_int(event.get("completed")) or 0
        if completed >= total:
            self._start_phase("codegraph", "[cyan]Finalizing CodeGraph...[/cyan]")
            return
        self._progress.update(
            self._tasks["codegraph"],
            total=total,
            completed=completed,
            description="[cyan]Building CodeGraph[/cyan]",
        )

    def _graph_done(self, event: Mapping[str, Any]):
        self._set_summary(
            "codegraph",
            "CodeGraph ready: "
            f"{event.get('nodes', 0)} functions, "
            f"{event.get('edges', 0)} calls",
        )

    def _graph_reused(self, event: Mapping[str, Any]):
        self._set_summary("codegraph", "CodeGraph reused")

    def _reachability_phase_progress(self, event: Mapping[str, Any]) -> None:
        description, unit = self._REACHABILITY_PHASES.get(
            str(event.get("phase") or ""),
            ("Running reachability", "items"),
        )
        total = _positive_int(event.get("total"))
        completed = _non_negative_int(event.get("completed")) or 0
        self._progress.update(
            self._tasks["reachability"],
            total=total,
            completed=min(completed, total) if total is not None else completed,
            description=(
                f"[cyan]{description} {completed}/{total or '?'} {unit}[/cyan]"
            ),
        )

    def _frontier_review_start(self, event: Mapping[str, Any]):
        self._start_phase(
            "reachability",
            (
                "[cyan]Deriving reachability contracts: "
                f"{event.get('nodes', 0)} functions, "
                f"{event.get('edges', 0)} calls[/cyan]"
            ),
        )

    def _frontier_review_done(self, event: Mapping[str, Any]):
        failed_nodes = _non_negative_int(event.get("failed_nodes")) or 0
        incomplete_nodes = (
            _non_negative_int(event.get("evidence_incomplete_nodes")) or 0
        )
        self._set_summary(
            "reachability",
            "Reachability complete: "
            f"{event.get('reviewed_nodes', 0)}/"
            f"{event.get('planned_nodes', 0)} functions, "
            f"{event.get('findings', 0)} findings, "
            f"functions with review failures: {failed_nodes}, "
            f"functions with incomplete evidence: {incomplete_nodes}",
        )

    def _findings_finalization_start(self, event: Mapping[str, Any]):
        candidates = event.get("candidates", 0)
        self._start_phase(
            "finding_dedup",
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
            self._progress.update(self._tasks["finding_dedup"], description=description)
            return
        self._progress.update(
            self._tasks["finding_dedup"],
            total=total,
            completed=min(completed, total),
            description=description,
        )

    def _findings_finalization_done(self, event: Mapping[str, Any]):
        self._set_summary(
            "finding_dedup",
            "Dedup complete: "
            f"{event.get('deduped_findings', 0)} kept, "
            f"{event.get('removed_findings', 0)} removed from "
            f"{event.get('raw_findings', 0)} candidates",
        )

    def _code_review_done(self, event: Mapping[str, Any]):
        self._set_summary(
            "reachability",
            "Reachability output: "
            f"{event.get('findings', 0)} findings across "
            f"{event.get('files', 0)} files",
        )

    def _print_phase(self, message: str):
        console = getattr(self._progress, "console", None)
        if console is not None:
            console.print(message)

    def _start_phase(
        self,
        node: str,
        description: str,
        *,
        total=None,
        print_message=None,
    ):
        if print_message is not None:
            self._print_phase(print_message)
        self._progress.update(
            self._tasks[node],
            description=description,
            total=total,
            completed=0,
        )

    def _finish_node(self, node: str, description: str) -> None:
        self._finished_nodes.add(node)
        self._progress.update(
            self._tasks[node],
            description=description,
            total=1,
            completed=1,
        )

    def _set_summary(self, node: str, summary: str) -> None:
        self._node_summaries[node] = summary
        self._start_phase(node, f"[cyan]{summary}[/cyan]", total=1)


class ExecutionGraphProgressReporter:
    def __init__(self, progress: Progress) -> None:
        self._progress = progress
        self._stage = ""
        self._review: ReviewCodeProgressReporter | None = None
        self._triage: TriageProgressReporter | None = None
        self._triage_task: TaskID | None = None
        self._triage_failed = False

    def __call__(self, event: Mapping[str, Any] | None) -> None:
        event = event or {}
        kind = str(event.get("event") or "")
        if kind == "execution_stage_start":
            self._start_stage(str(event.get("stage") or "unknown"))
            return
        if self._stage == "review" and self._review is not None:
            self._review(event)
            return
        if self._stage == "triage" and self._triage is not None:
            self._triage_event(kind, event)
            return
        if kind == "execution_node_start":
            self._print_node(event)
        elif kind == "execution_node_end":
            self._print_node_end(event)

    def finish(self) -> None:
        if self._review is not None:
            self._review.finish()
        if self._triage is not None and not self._triage_failed:
            self._triage.finish()
        self._snapshot_stage()

    def _start_stage(self, stage: str) -> None:
        self._remove_stage_tasks()
        self._stage = stage
        self._progress.console.rule(
            _stage_progress_label(stage).title(),
            style="cyan",
        )
        if stage == "review":
            self._review = ReviewCodeProgressReporter(self._progress)
        elif stage == "triage":
            self._triage_failed = False
            self._triage_task = self._progress.add_task(
                "[cyan]Starting triage...[/cyan]",
                total=1,
            )
            self._triage = TriageProgressReporter(
                self._progress,
                self._triage_task,
            )

    def _remove_stage_tasks(self) -> None:
        self.finish()
        if self._review is not None:
            self._review.remove()
            self._review = None
        if self._triage_task is not None:
            self._progress.remove_task(self._triage_task)
            self._triage_task = None
            self._triage = None

    def _snapshot_stage(self) -> None:
        if self._review is None and self._triage_task is None:
            return
        self._progress.console.print(self._progress.get_renderable())

    def _triage_event(self, kind: str, event: Mapping[str, Any]) -> None:
        assert self._triage is not None
        if kind in {"start", "progress", "done", "error"}:
            self._triage(event)
        elif kind == "execution_node_start":
            self._print_node(event)
            if event.get("node") == "triage" and self._triage_task is not None:
                self._progress.update(
                    self._triage_task,
                    description="[cyan]Triage running...[/cyan]",
                )
        elif kind == "execution_node_end":
            if event.get("node") == "triage":
                if event.get("status") == "error" and self._triage_task is not None:
                    self._triage_failed = True
                    self._progress.update(
                        self._triage_task,
                        description="[red]Triage failed[/red]",
                    )
                else:
                    self._triage.finish()
            else:
                self._print_node_end(event)
        elif kind == "execution_stage_end" and not self._triage_failed:
            self._triage.finish()

    def _print_node(self, event: Mapping[str, Any]) -> None:
        self._progress.console.print(_node_start_description(event, self._stage))

    def _print_node_end(self, event: Mapping[str, Any]) -> None:
        self._progress.console.print(_node_completion_description(event))


def _node_completion_description(event: Mapping[str, Any]) -> str:
    stage = escape(str(event.get("stage") or "unknown"))
    node = escape(str(event.get("node") or "unknown"))
    if event.get("status") == "error":
        return f"[red]✗ {stage}.{node} failed[/red]"
    if event.get("status") == "inconclusive":
        return f"[yellow]! {stage}.{node} inconclusive[/yellow]"
    return f"[green]✓ {stage}.{node} complete[/green]"


def _node_start_description(
    event: Mapping[str, Any],
    fallback_stage: str = "unknown",
) -> str:
    stage = escape(str(event.get("stage") or fallback_stage))
    node = escape(str(event.get("node") or "unknown"))
    return f"[cyan]Node:[/cyan] {stage}.{node}"


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


def _review_event_node(event: Mapping[str, Any]) -> str:
    return (
        "reachability" if event.get("node") == "reachability" else "simple_llm_review"
    )


def _stage_progress_label(stage: object) -> str:
    name = str(stage or "unknown")
    return escape("init" if name == "initialize" else name)
