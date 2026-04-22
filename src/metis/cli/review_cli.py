# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from rich.markup import escape

from .utils import print_console


def make_review_debug_callback(args):
    log_level = str(getattr(args, "log_level", "") or "").upper()
    if log_level != "DEBUG" or not bool(getattr(args, "verbose", False)):
        return None

    def _clip(value, limit=900):
        text = str(value or "")
        if len(text) <= limit:
            return text
        return text[:limit] + "\n...[truncated]"

    def _summarize_text(value):
        text = str(value or "")
        lines = text.splitlines()
        return f"chars={len(text)} lines={len(lines)}"

    def _looks_like_error_text(tool_name: str, tool_output: str) -> bool:
        text = str(tool_output or "").strip()
        if not text:
            return False
        lowered = text.lower()
        if text.startswith("Tool execution failed:"):
            return True
        if "no such file" in lowered or "not found" in lowered:
            return True
        if "failed:" in lowered or "error" in lowered:
            return True
        if tool_name in {"cat", "sed", "grep"} and len(text.splitlines()) == 1:
            return True
        return False

    def _callback(event):
        if event.get("event") != "tool_call":
            return
        tool_name = str(event.get("tool_name", "unknown"))
        print_console(
            f"[bright_black]-- review debug: tool {escape(tool_name)} --[/bright_black]",
            args.quiet,
        )
        print_console(escape(_clip(event.get("tool_args"))), args.quiet)
        tool_output = event.get("tool_output")
        if isinstance(tool_output, str):
            show_full_output = tool_name in {"rag_search", "project_context_rag"}
            summary = f"tool_output {_summarize_text(tool_output)}"
            if not show_full_output:
                summary += " (omitted)"
            if _looks_like_error_text(tool_name, tool_output):
                summary += " [possible error text]"
            print_console(f"[bright_black]{summary}[/bright_black]", args.quiet)
            if show_full_output or str(tool_output or "").startswith(
                "Tool execution failed:"
            ):
                print_console(
                    escape(str(tool_output)),
                    args.quiet,
                )
            return
        print_console(
            f"[bright_black]tool_output_type={escape(type(tool_output).__name__)}[/bright_black]",
            args.quiet,
        )
        print_console(escape(_clip(tool_output)), args.quiet)

    return _callback
