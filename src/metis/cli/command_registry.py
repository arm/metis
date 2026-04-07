# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from prompt_toolkit.completion import WordCompleter
from rich.markup import escape

from .commands import (
    run_ask,
    run_file_review,
    run_index,
    run_review,
    run_review_code,
    run_triage,
    run_update,
    show_help,
    show_version,
)
from .utils import print_console


InvocationMode = Literal["none", "path", "question", "index", "args"]


@dataclass(frozen=True)
class CommandSpec:
    handler: Callable[..., object] | None
    tracked: bool = False
    invocation_mode: InvocationMode = "none"
    include_target_in_display_name: bool = False
    prepares_output_file: bool = False

    def usage_target(self, cmd_args: list[str]) -> str | None:
        if self.invocation_mode == "path" and cmd_args:
            return cmd_args[0]
        return None

    def usage_display_name(self, cmd: str, cmd_args: list[str]) -> str:
        target = self.usage_target(cmd_args)
        if not self.include_target_in_display_name or not target:
            return cmd
        return f"{cmd} {Path(target).name}"

    def validate(self, cmd: str, cmd_args: list[str], args) -> bool:
        if self.invocation_mode == "path" and not cmd_args:
            print_console(
                f"[red]Error:[/red] Command '{escape(cmd)}' requires a file path argument.",
                args.quiet,
            )
            return False
        return True

    def invoke(self, engine, cmd_args: list[str], args) -> None:
        if self.handler is None:
            return
        if self.invocation_mode == "path":
            self.handler(engine, cmd_args[0], args)
            return
        if self.invocation_mode == "question":
            self.handler(engine, " ".join(cmd_args), args)
            return
        if self.invocation_mode == "index":
            self.handler(engine, args.verbose, args.quiet)
            return
        if self.invocation_mode == "args":
            self.handler(engine, args)
            return
        self.handler()


COMMANDS = {
    "index": CommandSpec(
        run_index,
        tracked=True,
        invocation_mode="index",
        prepares_output_file=True,
    ),
    "review_patch": CommandSpec(
        run_review,
        tracked=True,
        invocation_mode="path",
        include_target_in_display_name=True,
        prepares_output_file=True,
    ),
    "review_code": CommandSpec(
        run_review_code,
        tracked=True,
        invocation_mode="args",
        prepares_output_file=True,
    ),
    "update": CommandSpec(
        run_update,
        invocation_mode="path",
        prepares_output_file=True,
    ),
    "review_file": CommandSpec(
        run_file_review,
        tracked=True,
        invocation_mode="path",
        include_target_in_display_name=True,
        prepares_output_file=True,
    ),
    "ask": CommandSpec(
        run_ask,
        tracked=True,
        invocation_mode="question",
        prepares_output_file=True,
    ),
    "triage": CommandSpec(
        run_triage,
        tracked=True,
        invocation_mode="path",
        include_target_in_display_name=True,
        prepares_output_file=True,
    ),
    "help": CommandSpec(show_help),
    "version": CommandSpec(show_version),
    "exit": CommandSpec(None),
}

completer = WordCompleter(list(COMMANDS), ignore_case=True)
