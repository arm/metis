# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections import Counter

from rich.markup import escape
from rich.progress import Progress
from rich.progress import TaskID

from .utils import build_standard_progress, with_spinner, print_console


def run_triage_action(args, *, action, spinner_text):
    debug_cb = _make_triage_debug_callback(args)
    if getattr(args, "verbose", False):

        def _runner(progress_callback):
            return action(
                debug_callback=debug_cb,
                progress_callback=progress_callback,
            )

        return _run_with_triage_progress(_runner)

    return with_spinner(
        spinner_text,
        action,
        debug_callback=debug_cb,
        quiet=args.quiet,
    )


def _run_with_triage_progress(runner):
    with build_standard_progress(transient=False) as progress:
        task = progress.add_task("[cyan]Triaging findings...[/cyan]", total=1)
        callback = TriageProgressReporter(progress, task)
        result = runner(callback)
        callback.finish()
    return result


class TriageProgressReporter:
    def __init__(self, progress: Progress, task: TaskID) -> None:
        self._progress = progress
        self._task = task
        self._completed = 0
        self._total: int | None = None
        self._statuses: Counter[str] = Counter()

    def __call__(self, event) -> None:
        total = event.get("total", 0)
        if isinstance(total, int) and total > 0 and self._total != total:
            self._total = total

        kind = event.get("event")
        if kind == "progress":
            completed = event.get("completed")
            if isinstance(completed, int) and completed >= 0:
                self._completed = max(self._completed, completed)
            self._progress.update(
                self._task,
                total=self._total,
                completed=self._completed,
                description=self._progress_description(),
            )
            return
        if kind == "done":
            decision = event.get("decision") or {}
            normalized = str(decision.get("status", "unknown")).lower()
            self._statuses[normalized] += 1
            self._progress.update(
                self._task,
                completed=self._completed,
                description=self._progress_description(),
            )
        elif kind == "error":
            self._statuses["error"] += 1
            self._progress.update(
                self._task,
                completed=self._completed,
                description=self._progress_description(),
            )

    def _progress_description(self) -> str:
        return f"[cyan]Triaging findings {self._completed}/{self._total or '?'}[/cyan]"

    def finish(self) -> None:
        if self._total is not None:
            completed = min(self._completed, self._total)
        else:
            completed = 1
        styles = (
            ("valid", "Valid", "green"),
            ("invalid", "Invalid", "red"),
            ("inconclusive", "Inconclusive", "yellow"),
            ("error", "Error", "red"),
        )
        summary = " ".join(
            f"[{color}]{label}: {self._statuses[status]}[/{color}]"
            for status, label, color in styles
            if self._statuses[status]
        )
        self._progress.update(
            self._task,
            completed=completed,
            description=summary or "[green]No findings[/green]",
        )


def _make_triage_debug_callback(args):
    log_level = str(getattr(args, "log_level", "") or "").upper()
    if log_level != "DEBUG":
        return None

    def _debug_print(message, **kwargs):
        print_console(message, quiet=False, **kwargs)

    def _clip(value, limit=900):
        text = str(value or "")
        if len(text) <= limit:
            return text
        return text[:limit] + "\n...[truncated]"

    def _summarize_text(value):
        text = str(value or "")
        lines = text.splitlines()
        return f"chars={len(text)} lines={len(lines)}"

    def _callback(event):
        kind = event.get("event")
        if kind == "retrieval":
            _debug_print(
                "[bright_black]-- triage debug: retrieval query --[/bright_black]"
            )
            _debug_print(
                f"[bright_black]query {_summarize_text(event.get('query'))} (omitted)[/bright_black]"
            )
            context_text = str(event.get("context") or "")
            _debug_print(
                f"[bright_black]-- triage debug: rag context chars={len(context_text)} (omitted) --[/bright_black]"
            )
            return
        if kind == "model_input":
            stage = event.get("stage", "unknown")
            _debug_print(
                f"[bright_black]-- triage debug: model input ({escape(str(stage))}) --[/bright_black]"
            )
            user_prompt = str(event.get("user_prompt") or "")
            _debug_print(
                f"[bright_black]user: chars={len(user_prompt)} (omitted)[/bright_black]"
            )
            return
        if kind == "tool_call":
            tool_name = str(event.get("tool_name", "unknown"))
            _debug_print(
                f"[bright_black]-- triage debug: tool {escape(tool_name)} --[/bright_black]"
            )
            _debug_print(escape(_clip(event.get("tool_args"))))
            tool_output = event.get("tool_output")
            if isinstance(tool_output, str):
                _debug_print(
                    f"[bright_black]tool_output {_summarize_text(tool_output)} (omitted)[/bright_black]"
                )
            else:
                _debug_print(
                    f"[bright_black]tool_output_type={escape(type(tool_output).__name__)}[/bright_black]"
                )
                _debug_print(escape(_clip(tool_output)))
            return
        if kind == "model_output":
            status = event.get("decision_status", "")
            reason = event.get("decision_reason", "")
            _debug_print(
                f"[bright_black]-- triage debug: model output status={escape(str(status))} --[/bright_black]"
            )
            _debug_print(escape(_clip(reason)))
            return
        if kind == "status_adjudication":
            _debug_print(
                "[bright_black]-- triage debug: status adjudication --[/bright_black]"
            )
            _debug_print(escape(_clip(event)))

    return _callback
