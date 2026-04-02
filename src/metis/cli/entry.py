# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import argparse
from datetime import datetime
import logging
from pathlib import Path

from rich.markup import escape
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory

from metis.configuration import load_runtime_config
from metis.engine import MetisEngine
from metis.usage import UsageRuntime
from metis.utils import read_file_content
from metis.providers.registry import get_provider

try:
    from metis.vector_store.pgvector_store import PGVectorStoreImpl
except ImportError:
    pass


from .commands import (
    run_index,
    run_ask,
    run_review,
    run_file_review,
    run_review_code,
    run_triage,
    run_update,
    show_help,
    show_version,
)
from .utils import (
    configure_logger,
    PG_SUPPORTED,
    build_pg_backend,
    build_chroma_backend,
    print_console,
    print_usage_summary,
    print_final_usage_summary,
)

logging.captureWarnings(True)
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger("metis")

COMMANDS = {
    "index": run_index,
    "review_patch": run_review,
    "review_code": run_review_code,
    "update": run_update,
    "review_file": run_file_review,
    "ask": run_ask,
    "triage": run_triage,
    "help": show_help,
    "version": show_version,
    "exit": None,
}
completer = WordCompleter(list(COMMANDS), ignore_case=True)
TRACKED_COMMANDS = {
    "index",
    "review_patch",
    "review_code",
    "review_file",
    "ask",
    "triage",
}
EXIT_REQUESTED = object()


def determine_output_file(cmd, args, cmd_args):
    """Set args.output_file list if not provided, or extract from cmd_args."""
    existing_outputs = list(args.output_file or [])
    overrides: list[str] = []

    while "--output-file" in cmd_args:
        idx = cmd_args.index("--output-file")
        if idx + 1 < len(cmd_args):
            overrides.append(cmd_args[idx + 1])
        del cmd_args[idx : idx + 2]

    if overrides:
        args.output_file = overrides
        return

    if cmd == "triage":
        args.output_file = existing_outputs
        return

    if existing_outputs:
        args.output_file = existing_outputs
        return

    Path("results").mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    args.output_file = [f"results/{cmd}_{timestamp}.json"]


def resolve_custom_prompt(args):
    custom_prompt_text = None
    if args.custom_prompt:
        pf = Path(args.custom_prompt)
        if pf.is_file() and pf.suffix.lower() in {".md", ".txt"}:
            custom_prompt_text = read_file_content(str(pf))
        else:
            print_console(
                f"[yellow]Warning:[/yellow] Ignoring --custom-prompt '{escape(str(pf))}'. It must exist and have .md or .txt extension.",
                args.quiet,
            )
    if custom_prompt_text is None:
        metis_md = Path(args.codebase_path) / ".metis.md"
        if metis_md.is_file():
            custom_prompt_text = read_file_content(str(metis_md))
    return custom_prompt_text


def build_engine(args, runtime):
    llm_provider_name = runtime.get("llm_provider_name", "openai")
    provider_cls = get_provider(llm_provider_name)
    llm_provider = provider_cls(runtime)

    usage_runtime = UsageRuntime(args.codebase_path)
    embed_model_code = llm_provider.get_embed_model_code(
        callback_manager=usage_runtime.llamaindex_callback_manager
    )
    embed_model_docs = llm_provider.get_embed_model_docs(
        callback_manager=usage_runtime.llamaindex_callback_manager
    )

    if args.backend == "postgres":
        vector_backend = build_pg_backend(
            args, runtime, embed_model_code, embed_model_docs
        )
    else:
        vector_backend = build_chroma_backend(
            args, runtime, embed_model_code, embed_model_docs
        )

    engine = MetisEngine(
        codebase_path=args.codebase_path,
        llm_provider=llm_provider,
        vector_backend=vector_backend,
        custom_prompt_text=resolve_custom_prompt(args),
        usage_runtime=usage_runtime,
        **runtime,
    )
    return engine, vector_backend


def _usage_target(cmd, cmd_args):
    if cmd in {"review_patch", "review_file", "triage"} and cmd_args:
        return cmd_args[0]
    return None


def _usage_display_name(cmd, cmd_args):
    target = _usage_target(cmd, cmd_args)
    if not target:
        return cmd
    return f"{cmd} {Path(target).name}"


def _invoke_command(func, engine, cmd, cmd_args, args):
    if cmd in ("review_patch", "review_file", "update", "triage"):
        func(engine, cmd_args[0], args)
    elif cmd == "ask":
        func(engine, " ".join(cmd_args), args)
    elif cmd == "index":
        func(engine, args.verbose, args.quiet)
    elif cmd == "review_code":
        func(engine, args)


def finalize_cli_session(engine, args):
    if getattr(args, "_metis_usage_finalized", False):
        return None
    args._metis_usage_finalized = True
    if engine is None or not hasattr(engine, "has_usage") or not engine.has_usage():
        return None
    saved_path = engine.save_usage_summary()
    print_final_usage_summary(engine.usage_totals(), saved_path=saved_path)
    return saved_path


def finalize_cli_session_and_close(engine, args, farewell):
    try:
        finalize_cli_session(engine, args)
    finally:
        if farewell:
            print_console(farewell, args.quiet, force=True)
        close_fn = getattr(engine, "close", None)
        if callable(close_fn):
            close_fn()


def execute_command(engine, cmd, cmd_args, args):
    if cmd not in COMMANDS:
        print_console(f"[red]Unknown command:[/red] {escape(cmd)}", args.quiet)
        return

    if cmd == "exit":
        return EXIT_REQUESTED

    if cmd == "version":
        show_version()
        return

    if cmd == "help":
        show_help()
        return

    determine_output_file(cmd, args, cmd_args)
    func = COMMANDS[cmd]
    tracked = cmd in TRACKED_COMMANDS
    usage_command = None
    if tracked:
        usage_command = engine.usage_command(
            cmd,
            target=_usage_target(cmd, cmd_args),
            display_name=_usage_display_name(cmd, cmd_args),
        )

    if cmd in ("review_patch", "review_file", "update", "triage") and not cmd_args:
        print_console(
            f"[red]Error:[/red] Command '{escape(cmd)}' requires a file path argument.",
            args.quiet,
        )
        return

    if usage_command is None:
        _invoke_command(func, engine, cmd, cmd_args, args)
        return

    with usage_command as command:
        _invoke_command(func, engine, cmd, cmd_args, args)

    record = engine.finalize_usage_command(command)
    print_usage_summary(
        record["display_name"],
        record["summary"],
        record["cumulative"],
    )


def run_non_interactive(engine, args):
    args.quiet = not args.verbose
    if not args.command:
        print_console(
            "[red]Error:[/red] --command is required in non-interactive mode.",
            args.quiet,
        )
        return 1, None
    parts = args.command.strip().split()
    cmd, cmd_args = parts[0], parts[1:]
    try:
        result = execute_command(engine, cmd, cmd_args, args)
    except Exception as e:
        print_console(f"[bold red]Error:[/bold red] {escape(str(e))}", args.quiet)
        return 1, None
    farewell = "[magenta]Goodbye![/magenta]" if result is EXIT_REQUESTED else None
    return 0, farewell


def run_interactive_loop(engine, args, vector_backend):
    print_console(
        "[bold cyan]Metis CLI. Type 'help' for usage, 'exit' to quit.[/bold cyan]",
        args.quiet,
    )
    history = InMemoryHistory()

    while True:
        try:
            user_input = prompt("> ", completer=completer, history=history).strip()
            if not user_input:
                continue
            parts = user_input.split()
            cmd, cmd_args = parts[0], parts[1:]

            if PG_SUPPORTED and isinstance(vector_backend, PGVectorStoreImpl):
                if cmd == "index" and vector_backend.check_project_schema_exists():
                    print_console(
                        "[red]Schema exists. Cannot re-index.[/red]", args.quiet
                    )
                    continue
                if (
                    cmd in {"ask", "review_code", "review_file"}
                    and not vector_backend.check_project_schema_exists()
                ):
                    print_console(
                        "[red]Schema missing. Did you forget to index?[/red]",
                        args.quiet,
                    )
                    continue

            result = execute_command(engine, cmd, cmd_args, args)
            if result is EXIT_REQUESTED:
                return "[magenta]Goodbye![/magenta]"

        except (EOFError, KeyboardInterrupt):
            return "\n[magenta]Bye![/magenta]"
        except Exception as e:
            print_console(f"[bold red]Error:[/bold red] {escape(str(e))}", args.quiet)


def main():
    parser = argparse.ArgumentParser(
        description="Metis: AI security focused code review.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--project-schema", type=str, default="myproject-main")
    parser.add_argument("--chroma-dir", type=str, default="./chromadb")
    parser.add_argument("--codebase-path", type=str, default=".")
    parser.add_argument(
        "--backend", type=str, default="chroma", choices=["chroma", "postgres"]
    )
    parser.add_argument("--log-file", type=str)
    parser.add_argument("--log-level", type=str, default="ERROR")
    parser.add_argument(
        "--custom-prompt",
        type=str,
        help="Path to a custom prompt file (.md or .txt) used to guide analysis",
    )
    parser.add_argument("--version", action="store_true", help="Show program version")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress output in CLI"
    )
    parser.add_argument(
        "--output-file",
        action="append",
        help="Save analysis results to this file (repeatable, supports .json/.html/.sarif)",
    )
    parser.add_argument(
        "--output-files",
        nargs="+",
        help="Alternative syntax to provide multiple output files",
    )
    parser.add_argument(
        "--non-interactive", action="store_true", help="Run in non-interactive mode"
    )
    parser.add_argument(
        "--command",
        type=str,
        help="Command to run in non-interactive mode (e.g., 'review_patch file.patch')",
    )
    parser.add_argument(
        "--triage",
        action="store_true",
        help="After review commands, triage findings and annotate SARIF output.",
    )
    parser.add_argument(
        "--include-triaged",
        action="store_true",
        help="Include findings already triaged by Metis when running triage.",
    )

    args = parser.parse_args()

    if args.output_files:
        if args.output_file:
            args.output_file.extend(args.output_files)
        else:
            args.output_file = list(args.output_files)
        args.output_files = None

    if args.quiet and args.verbose:
        print_console(
            "[red]Error:[/red] --quiet and --verbose cannot be used together.",
            False,
        )
        exit(1)
    if args.version:
        show_version()
        return

    configure_logger(logger, args)
    runtime = load_runtime_config(enable_psql=(args.backend == "postgres"))
    engine, vector_backend = build_engine(args, runtime)
    exit_code = 0
    farewell = None
    try:
        if args.non_interactive:
            exit_code, farewell = run_non_interactive(engine, args)
            return

        farewell = run_interactive_loop(engine, args, vector_backend)
    finally:
        finalize_cli_session_and_close(engine, args, farewell)
    if exit_code:
        raise SystemExit(exit_code)
