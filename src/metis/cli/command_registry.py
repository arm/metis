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


InvocationMode = Literal["none", "path", "question", "index", "args", "meta"]
IndexPolicy = Literal["none", "required", "optional"]


@dataclass(frozen=True)
class CommandSpec:
    handler: Callable[..., object] | None
    tracked: bool = False
    invocation_mode: InvocationMode = "none"
    include_target_in_display_name: bool = False
    prepares_output_file: bool = False
    index_policy: IndexPolicy = "none"
    supports_triage: bool = False

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

    def validate_options(self, cmd: str, args, *, ignore_index_requested: bool) -> bool:
        triage_requested = bool(getattr(args, "triage", False))
        strict_triage_validation = bool(getattr(args, "non_interactive", False))
        if (
            triage_requested
            and strict_triage_validation
            and cmd != "triage"
            and not self.supports_triage
        ):
            print_console(
                "[red]Error:[/red] --triage can only be used with review_code, review_file, or review_patch.",
                args.quiet,
            )
            return False
        if ignore_index_requested and self.index_policy != "optional":
            print_console(
                "[red]Error:[/red] --ignore-index can only be used with review_code, review_file, review_patch, or triage.",
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
        index_policy="optional",
        supports_triage=True,
    ),
    "review_code": CommandSpec(
        run_review_code,
        tracked=True,
        invocation_mode="args",
        prepares_output_file=True,
        index_policy="optional",
        supports_triage=True,
    ),
    "update": CommandSpec(
        run_update,
        invocation_mode="path",
        prepares_output_file=True,
        index_policy="required",
    ),
    "review_file": CommandSpec(
        run_file_review,
        tracked=True,
        invocation_mode="path",
        include_target_in_display_name=True,
        prepares_output_file=True,
        index_policy="optional",
        supports_triage=True,
    ),
    "ask": CommandSpec(
        run_ask,
        tracked=True,
        invocation_mode="question",
        prepares_output_file=True,
        index_policy="required",
    ),
    "triage": CommandSpec(
        run_triage,
        tracked=True,
        invocation_mode="path",
        include_target_in_display_name=True,
        prepares_output_file=True,
        index_policy="optional",
    ),
    "help": CommandSpec(show_help, invocation_mode="meta"),
    "version": CommandSpec(show_version, invocation_mode="meta"),
    "exit": CommandSpec(None),
}

completer = WordCompleter(list(COMMANDS), ignore_case=True)
