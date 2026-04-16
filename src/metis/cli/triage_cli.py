# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from rich.markup import escape

from .utils import build_standard_progress, with_spinner, print_console


def run_triage_action(args, *, action, spinner_text):
    debug_cb = _make_triage_debug_callback(args)
    if getattr(args, "verbose", False):

        def _runner(progress_cb):
            kwargs = _build_triage_kwargs(
                args,
                debug_cb=debug_cb,
                progress_cb=progress_cb,
            )
            return action(kwargs)

        return _run_with_triage_progress(args, _runner)

    kwargs = _build_triage_kwargs(args, debug_cb=debug_cb)
    return with_spinner(spinner_text, action, kwargs, quiet=args.quiet)


def _run_with_triage_progress(args, runner):
    with build_standard_progress(transient=True) as progress:
        task = progress.add_task("[cyan]Triaging findings...[/cyan]", total=1)
        callback = _make_triage_progress_callback(args, progress, task)
        result = runner(callback)
        final_total = callback.state["total"]
        final_completed = callback.state["completed"]
        if final_total and final_total > 0:
            progress.update(task, completed=min(final_completed, final_total))
        else:
            progress.update(task, completed=1)
    return result


def _build_triage_kwargs(args, *, debug_cb=None, progress_cb=None):
    kwargs = {
        "include_triaged": bool(getattr(args, "include_triaged", False)),
    }
    if debug_cb is not None:
        kwargs["debug_callback"] = debug_cb
    if progress_cb is not None:
        kwargs["progress_callback"] = progress_cb
    return kwargs


def _make_triage_progress_callback(args, progress, task):
    class _ProgressCb:
        def __init__(self):
            self.state = {"completed": 0, "total": None}

        def __call__(self, event):
            finding = event.get("finding")
            total = event.get("total", 0)
            if isinstance(total, int) and total > 0 and self.state["total"] != total:
                self.state["total"] = total
                progress.update(task, total=total)

            file_part = ""
            line_part = ""
            if finding is not None:
                file_path = getattr(finding, "file_path", "") or "<unknown>"
                line_no = getattr(finding, "line", 1)
                file_part = file_path
                line_part = (
                    f":{line_no}" if isinstance(line_no, int) and line_no > 0 else ""
                )

            kind = event.get("event")
            if kind == "start":
                progress.update(
                    task,
                    description=f"[cyan]Triaging {escape(file_part)}{line_part}[/cyan]",
                )
                return

            if kind in {"done", "error"}:
                self.state["completed"] += 1

            if kind == "done":
                decision = event.get("decision") or {}
                status = str(decision.get("status", "unknown"))
                normalized = status.lower()
                if normalized == "invalid":
                    status_color = "red"
                elif normalized == "inconclusive":
                    status_color = "yellow"
                else:
                    status_color = "green"
                progress.console.print(
                    f"[{status_color}]{escape(status)}[/{status_color}] {escape(file_part)}{line_part}"
                )
                progress.update(
                    task,
                    completed=self.state["completed"],
                    description=(
                        f"[cyan]Triaging {escape(file_part)}{line_part} -> "
                        f"[{status_color}]{escape(status)}[/{status_color}][/cyan]"
                    ),
                )
            elif kind == "error":
                progress.update(
                    task,
                    completed=self.state["completed"],
                    description=f"[yellow]Triage failed {escape(file_part)}{line_part}[/yellow]",
                )

    return _ProgressCb()


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
