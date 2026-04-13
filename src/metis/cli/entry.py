# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import argparse
from datetime import datetime
import logging
from pathlib import Path

from rich.markup import escape
from prompt_toolkit import prompt
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


from .command_registry import COMMANDS, completer
from .command_runtime import CommandRuntime
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
        **usage_runtime.hooks.embed_model_kwargs()
    )
    embed_model_docs = llm_provider.get_embed_model_docs(
        **usage_runtime.hooks.embed_model_kwargs()
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


def finalize_cli_session(engine, args):
    if getattr(args, "_metis_usage_finalized", False):
        return None
    args._metis_usage_finalized = True
    if engine is None or not hasattr(engine, "has_usage") or not engine.has_usage():
        return None
    saved_path = engine.save_usage_summary()
    completed_commands = None
    usage_runtime = getattr(engine, "usage_runtime", None)
    completed_commands_fn = getattr(usage_runtime, "completed_commands", None)
    if callable(completed_commands_fn):
        try:
            completed_commands = completed_commands_fn()
        except Exception:
            completed_commands = None
    include_totals = not (
        bool(getattr(args, "non_interactive", False))
        and isinstance(completed_commands, list)
        and len(completed_commands) == 1
    )
    print_final_usage_summary(
        engine.usage_totals(),
        saved_path=saved_path,
        quiet=args.quiet,
        include_totals=include_totals,
    )
    return saved_path


def finalize_cli_session_and_close(engine, args, farewell):
    try:
        finalize_cli_session(engine, args)
    finally:
        if farewell:
            print_console(farewell, args.quiet)
        close_fn = getattr(engine, "close", None)
        if callable(close_fn):
            close_fn()


def _command_requests_ignore_index(args, cmd_args):
    filtered_args = []
    ignore_index = bool(getattr(args, "ignore_index", False))
    for arg in cmd_args:
        if arg == "--ignore-index":
            ignore_index = True
            continue
        filtered_args.append(arg)
    return filtered_args, ignore_index


def _prepare_command_runtime(cmd, cmd_args, args):
    spec = COMMANDS[cmd]
    filtered_args, ignore_index = _command_requests_ignore_index(args, cmd_args)
    if not spec.validate_options(cmd, args, ignore_index_requested=ignore_index):
        return None

    if spec.index_policy == "none":
        return CommandRuntime(
            command=cmd,
            command_args=filtered_args,
            use_retrieval_context=False,
        )

    if ignore_index and spec.index_policy == "optional":
        return CommandRuntime(
            command=cmd,
            command_args=filtered_args,
            use_retrieval_context=False,
        )

    return CommandRuntime(
        command=cmd,
        command_args=filtered_args,
        use_retrieval_context=True,
    )


def _interactive_command_ignores_index(cmd, cmd_args, args):
    spec = COMMANDS.get(cmd)
    if spec is None or spec.index_policy != "optional":
        return False
    _filtered_args, ignore_index = _command_requests_ignore_index(args, cmd_args)
    return ignore_index


def execute_command(engine, cmd, cmd_args, args):
    if cmd not in COMMANDS:
        print_console(f"[red]Unknown command:[/red] {escape(cmd)}", args.quiet)
        return

    spec = COMMANDS[cmd]
    if cmd == "exit":
        return EXIT_REQUESTED
    runtime = _prepare_command_runtime(cmd, list(cmd_args), args)
    if runtime is None:
        return

    if spec.prepares_output_file:
        determine_output_file(cmd, args, runtime.command_args)

    if not spec.validate(cmd, runtime.command_args, args):
        return

    usage_command = None
    if spec.tracked:
        usage_command = engine.usage_command(
            cmd,
            target=spec.usage_target(runtime.command_args),
            display_name=spec.usage_display_name(cmd, runtime.command_args),
        )

    if usage_command is None:
        spec.invoke(engine, runtime.command_args, args, runtime)
        return

    with usage_command as command:
        spec.invoke(engine, runtime.command_args, args, runtime)

    record = engine.finalize_usage_command(command)
    print_usage_summary(
        record["display_name"],
        record["summary"],
        record["cumulative"],
        quiet=args.quiet,
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
                    and not _interactive_command_ignores_index(cmd, cmd_args, args)
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
    parser.add_argument(
        "--ignore-index",
        action="store_true",
        help="Allow selected analysis commands to run without an index-backed context.",
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
        COMMANDS["version"].invoke(None, [], args)
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
