# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from prompt_toolkit.completion import WordCompleter
from rich.markup import escape

from .command_runtime import CommandRuntime
from .commands import (
    run_ask,
    run_dir_review,
    run_file_review,
    run_init,
    run_index,
    run_review,
    run_review_code,
    run_triage,
    run_update,
    show_help,
    show_version,
)
from .utils import print_console


InvocationMode = Literal["none", "path", "question", "index", "args", "meta"]


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
        if self.invocation_mode == "path" and len(cmd_args) != 1:
            print_console(
                f"[red]Error:[/red] Command '{escape(cmd)}' requires exactly one file path argument.",
                args.quiet,
            )
            return False
        if self.invocation_mode not in {"path", "question"} and cmd_args:
            print_console(
                f"[red]Error:[/red] Command '{escape(cmd)}' does not accept positional arguments.",
                args.quiet,
            )
            return False
        if self.invocation_mode == "question" and not any(
            arg.strip() for arg in cmd_args
        ):
            print_console(
                f"[red]Error:[/red] Command '{escape(cmd)}' requires a question.",
                args.quiet,
            )
            return False
        return True

    def invoke(
        self,
        engine,
        cmd_args: list[str],
        args,
        runtime: CommandRuntime,
    ) -> None:
        if self.handler is None:
            return
        if self.invocation_mode == "path":
            self.handler(engine, cmd_args[0], args, runtime)
            return
        if self.invocation_mode == "question":
            self.handler(engine, " ".join(cmd_args), args, runtime)
            return
        if self.invocation_mode == "index":
            self.handler(engine, args.verbose, args.quiet)
            return
        if self.invocation_mode == "args":
            self.handler(engine, args, runtime)
            return
        if self.invocation_mode == "meta":
            self.handler(args)
            return
        self.handler()


COMMANDS = {
    "init": CommandSpec(
        run_init,
        tracked=True,
        invocation_mode="args",
        prepares_output_file=True,
    ),
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
    "review_dir": CommandSpec(
        run_dir_review,
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
    "help": CommandSpec(show_help, invocation_mode="meta"),
    "version": CommandSpec(show_version, invocation_mode="meta"),
    "exit": CommandSpec(None),
}

completer = WordCompleter(list(COMMANDS), ignore_case=True)
