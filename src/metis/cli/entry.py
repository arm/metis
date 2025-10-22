# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import argparse
import logging
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.markup import escape
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory

from metis.configuration import load_runtime_config
from metis.engine import MetisEngine
from metis.utils import read_file_content

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
)

console = Console()
logger = logging.getLogger("metis")

COMMANDS = {
    "index": run_index,
    "review_patch": run_review,
    "review_code": run_review_code,
    "update": run_update,
    "review_file": run_file_review,
    "ask": run_ask,
    "help": show_help,
    "version": show_version,
    "exit": None,
}
completer = WordCompleter(list(COMMANDS), ignore_case=True)


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

    if existing_outputs:
        args.output_file = existing_outputs
        return

    Path("results").mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    args.output_file = [f"results/{cmd}_{timestamp}.json"]


def execute_command(engine, cmd, cmd_args, args):
    if cmd not in COMMANDS:
        print_console(f"[red]Unknown command:[/red] {escape(cmd)}", args.quiet)
        return

    if cmd == "exit":
        print_console("[magenta]Goodbye![/magenta]", args.quiet)
        exit(0)

    if cmd == "version":
        show_version()
        return

    if cmd == "help":
        show_help()
        return

    determine_output_file(cmd, args, cmd_args)
    func = COMMANDS[cmd]

    if cmd in ("review_patch", "review_file", "update"):
        func(engine, cmd_args[0], args)
    elif cmd == "ask":
        func(engine, " ".join(cmd_args))
    elif cmd == "index":
        func(engine, args.verbose, args.quiet)
    elif cmd == "review_code":
        func(engine, args)


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
    parser.add_argument("--log-level", type=str, default="INFO")
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
    configure_logger(logger, args)
    runtime = load_runtime_config(enable_psql=(args.backend == "postgres"))

    # Construct the correct provider from runtime config
    llm_provider_name = runtime.get("llm_provider_name", "openai").lower()
    if llm_provider_name == "openai":
        from metis.providers.openai import OpenAIProvider

        llm_provider = OpenAIProvider(runtime)
    elif llm_provider_name == "azure_openai":
        from metis.providers.azure_openai import AzureOpenAIProvider

        llm_provider = AzureOpenAIProvider(runtime)

    embed_model_code = llm_provider.get_embed_model_code()
    embed_model_docs = llm_provider.get_embed_model_docs()

    if args.backend == "postgres":
        vector_backend = build_pg_backend(
            args, runtime, embed_model_code, embed_model_docs
        )
    else:
        vector_backend = build_chroma_backend(
            args, runtime, embed_model_code, embed_model_docs
        )

    # Resolve custom analysis prompt text
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
        # Fallback to .metis.md in project root (codebase path)
        metis_md = Path(args.codebase_path) / ".metis.md"
        if metis_md.is_file():
            custom_prompt_text = read_file_content(str(metis_md))

    engine = MetisEngine(
        codebase_path=args.codebase_path,
        llm_provider=llm_provider,
        vector_backend=vector_backend,
        custom_prompt_text=custom_prompt_text,
        **runtime,
    )

    if args.version:
        show_version()
        exit(0)

    if args.non_interactive:
        # In non-interactive mode, only print detailed output when --verbose is set
        args.quiet = not args.verbose
        if not args.command:
            print_console(
                "[red]Error:[/red] --command is required in non-interactive mode.",
                args.quiet,
            )
            exit(1)
        parts = args.command.strip().split()
        cmd, cmd_args = parts[0], parts[1:]
        try:
            execute_command(engine, cmd, cmd_args, args)
        except Exception as e:
            print_console(f"[bold red]Error:[/bold red] {escape(str(e))}", args.quiet)
            exit(1)
        exit(0)

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
                elif (
                    cmd in {"ask", "review_code", "review_file"}
                    and not vector_backend.check_project_schema_exists()
                ):
                    print_console(
                        "[red]Schema missing. Did you forget to index?[/red]",
                        args.quiet,
                    )
                    continue

            execute_command(engine, cmd, cmd_args, args)

        except (EOFError, KeyboardInterrupt):
            print_console("\n[magenta]Bye![/magenta]", args.quiet)
            break
        except Exception as e:
            print_console(f"[bold red]Error:[/bold red] {escape(str(e))}", args.quiet)
