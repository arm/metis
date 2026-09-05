# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import argparse
from copy import copy
from datetime import datetime
import logging
from pathlib import Path
import shlex
from typing import Any
from typing import cast
from uuid import uuid4

from rich.markup import escape
from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from yaml import YAMLError

from metis.configuration import build_embedding_provider_config, load_runtime_config
from metis.engine import MetisEngine
from metis.engine.execution import ExecutionResult
from metis.engine.execution import ExecutionStatus
from metis.usage import UsageRuntime
from metis.utils import read_file_content
from metis.providers.registry import get_chat_provider
from metis.providers.registry import get_embedding_provider
from metis import runlog

try:
    from metis.vector_store.pgvector_store import PGVectorStoreImpl
except ImportError:
    pass


from .command_registry import COMMANDS, completer
from .command_runtime import CommandRuntime
from .review_checkpoints import review_checkpoint_callbacks
from .review_progress import ExecutionGraphProgressReporter
from .utils import (
    configure_logger,
    PG_SUPPORTED,
    build_pg_backend,
    build_chroma_backend,
    build_qdrant_backend,
    build_standard_progress,
    print_console,
    print_execution_diagnostic,
    print_usage_summary,
    print_final_usage_summary,
    check_dir_exists,
    save_output,
    output_format,
    output_files_for_formats,
    output_path_identity,
    workflow_debug_context,
)

logging.captureWarnings(True)
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger("metis")
EXIT_REQUESTED = object()


def _execute_graph_with_progress(
    engine: Any,
    args: argparse.Namespace,
    callbacks: dict[str, object],
) -> ExecutionResult:
    kwargs = {"include_triaged": True if args.include_triaged else None}
    if not args.verbose:
        return engine.execute_graph(callbacks=callbacks, **kwargs)

    with build_standard_progress(transient=True) as progress:
        reporter = ExecutionGraphProgressReporter(progress)
        callbacks["progress_callback"] = reporter
        try:
            return engine.execute_graph(callbacks=callbacks, **kwargs)
        finally:
            reporter.finish()


def _save_graph_outputs(
    output_files,
    result: ExecutionResult,
    quiet,
    *,
    generated_output=False,
):
    outputs = result.outputs
    review = outputs.get("review", {})
    triage_result = outputs.get("triage", {})
    findings = review.get("findings")
    review_sarif = review.get("sarif")
    triage_sarif = triage_result.get("sarif")
    review_formats = tuple(review.get("formats", ()))
    triage_formats = tuple(triage_result.get("formats", ()))
    partial = result.status is ExecutionStatus.ERROR
    if partial:
        review_formats = tuple(
            name
            for name in review_formats
            if (review_sarif is not None if name == "sarif" else findings is not None)
        )
        if triage_sarif is None:
            triage_formats = ()
    review_filename = review.get("filename")
    triage_filename = triage_result.get("filename")
    explicit_output = bool(output_files) and not generated_output
    if (
        not explicit_output
        and review_formats
        and triage_formats
        and review_filename is not None
        and triage_filename is not None
    ):
        review_paths = {
            output_path_identity(Path(review_filename).with_suffix(f".{fmt}"))
            for fmt in review_formats
        }
        triage_paths = {
            output_path_identity(Path(triage_filename).with_suffix(f".{fmt}"))
            for fmt in triage_formats
        }
        if review_paths & triage_paths:
            raise ValueError("Output paths for graph stages must be distinct")
    review_files: list[str] = []
    triage_files: list[str] = []
    explicit_files = (output_files or ()) if explicit_output else ()
    for path in explicit_files:
        format_name = output_format(path)
        if format_name in triage_formats:
            triage_files.append(path)
        elif format_name in review_formats:
            review_files.append(path)
        elif triage_sarif is not None:
            triage_formats = (*triage_formats, format_name)
            triage_files.append(path)
        elif (
            review_sarif is not None if format_name == "sarif" else findings is not None
        ):
            review_formats = (*review_formats, format_name)
            review_files.append(path)
        elif partial:
            print_console(
                f"[yellow]No validated {format_name} output available for "
                f"{escape(str(path))}.[/yellow]",
                quiet,
            )
        else:
            raise ValueError(f"Execution graph did not produce {format_name} output")

    if triage_formats:
        if triage_sarif is None:
            raise ValueError("Execution graph did not produce triage results")
        triage_files = output_files_for_formats(
            triage_files
            if explicit_output or triage_filename is None
            else [triage_filename],
            triage_formats,
            command="graph_triage",
            generated_output=not explicit_output,
            reserved_paths={Path(path) for path in review_files},
        )
    if review_formats:
        if ("sarif" in review_formats and review_sarif is None) or (
            any(name != "sarif" for name in review_formats) and findings is None
        ):
            raise ValueError("Execution graph did not produce review results")
        review_files = output_files_for_formats(
            review_files
            if explicit_output or review_filename is None
            else [review_filename],
            review_formats,
            command="graph_review",
            generated_output=not explicit_output,
            reserved_paths={Path(path) for path in triage_files},
        )
        save_output(
            review_files,
            findings if findings is not None else review_sarif,
            quiet,
            sarif_payload=review_sarif,
        )
    if triage_formats:
        save_output(
            triage_files,
            triage_sarif,
            quiet,
            sarif_payload=triage_sarif,
        )


def determine_output_file(cmd, args, cmd_args):
    """Set args.output_file list if not provided, or extract from cmd_args."""
    existing_outputs = list(args.output_file or [])
    overrides: list[str] = []

    while "--output-file" in cmd_args:
        idx = cmd_args.index("--output-file")
        if (
            idx + 1 >= len(cmd_args)
            or not cmd_args[idx + 1]
            or cmd_args[idx + 1] == "--output-file"
        ):
            raise ValueError("--output-file requires a filename")
        overrides.append(cmd_args[idx + 1])
        del cmd_args[idx : idx + 2]

    if overrides:
        args.output_file = overrides
        args._metis_generated_output = False
        return

    if cmd == "triage":
        args.output_file = existing_outputs
        args._metis_generated_output = False
        return

    if existing_outputs:
        args.output_file = existing_outputs
        args._metis_generated_output = False
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    args.output_file = [f"results/{cmd}_{timestamp}_{uuid4().hex}.json"]
    args._metis_generated_output = True


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
    runtime = dict(runtime)
    engine_runtime = dict(runtime)

    llm_provider_name = runtime.get("llm_provider_name")
    if not llm_provider_name:
        raise RuntimeError("llm_provider configuration is required.")
    llm_provider_name = str(llm_provider_name)
    chat_provider_cls = get_chat_provider(llm_provider_name)
    engine_runtime.pop("llm_provider_name", None)
    engine_runtime.pop("llm_provider", None)

    embedding_provider = None
    embedding_provider_config = build_embedding_provider_config(
        cast(dict | None, runtime.get("embedding_provider_raw_config"))
    )
    llm_provider = chat_provider_cls(cast(dict, runtime["llm_provider"]))
    if embedding_provider_config is not None:
        embedding_provider_cls = get_embedding_provider(
            str(embedding_provider_config["name"])
        )
        embedding_provider = embedding_provider_cls(
            cast(dict, embedding_provider_config)
        )
    engine_runtime.pop("embedding_provider_raw_config", None)

    usage_runtime = UsageRuntime(args.codebase_path)

    if args.backend == "postgres":
        vector_backend = build_pg_backend(args, runtime, None, None)
    elif args.backend == "qdrant":
        vector_backend = build_qdrant_backend(args, runtime, None, None)
    else:
        vector_backend = build_chroma_backend(args, runtime, None, None)

    engine = MetisEngine(
        codebase_path=args.codebase_path,
        llm_provider=llm_provider,
        embedding_provider=embedding_provider,
        vector_backend=vector_backend,
        custom_prompt_text=resolve_custom_prompt(args),
        usage_runtime=usage_runtime,
        runlog=getattr(args, "_metis_runlog", None),
        **engine_runtime,
    )
    return engine, vector_backend


def finalize_cli_session(engine, args):
    if getattr(args, "_metis_usage_finalized", False):
        return None
    args._metis_usage_finalized = True
    if engine is None or not hasattr(engine, "has_usage") or not engine.has_usage():
        return None
    saved_path = engine.save_usage_summary()
    print_final_usage_summary(
        engine.usage_totals(),
        saved_path=saved_path,
        quiet=args.quiet,
    )
    return saved_path


def finalize_cli_session_and_close(engine, args, farewell):
    try:
        finalize_cli_session(engine, args)
    finally:
        close_fn = getattr(engine, "close", None)
        if callable(close_fn):
            close_fn()
        if farewell:
            print_console(farewell, args.quiet)


def execute_command(engine, cmd, cmd_args, args):
    with runlog.span(
        "command",
        cmd,
        lambda: {
            "arguments": list(cmd_args),
            "interactive": True,
        },
    ):
        return _execute_command(engine, cmd, cmd_args, args)


def _execute_command(engine, cmd, cmd_args, args):
    if cmd not in COMMANDS:
        print_console(f"[red]Unknown command:[/red] {escape(cmd)}", args.quiet)
        return

    spec = COMMANDS[cmd]
    args = copy(args)
    runtime = CommandRuntime(command=cmd, command_args=list(cmd_args))

    if spec.prepares_output_file:
        determine_output_file(cmd, args, runtime.command_args)

    if not spec.validate(cmd, runtime.command_args, args):
        return
    if cmd == "exit":
        return EXIT_REQUESTED

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
            parts = shlex.split(user_input)
            cmd, cmd_args = parts[0], parts[1:]

            if PG_SUPPORTED and isinstance(vector_backend, PGVectorStoreImpl):
                if cmd == "index" and vector_backend.check_project_schema_exists():
                    print_console(
                        "[red]Schema exists. Cannot re-index.[/red]", args.quiet
                    )
                    continue
                if cmd == "ask" and not vector_backend.check_project_schema_exists():
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
    parser.add_argument(
        "--config",
        type=str,
        help="Path to a custom Metis config file.",
    )
    parser.add_argument("--chroma-dir", type=str, default="./chromadb")
    parser.add_argument(
        "--qdrant-url",
        type=str,
        help="Qdrant server URL (default: http://localhost:6333).",
    )
    parser.add_argument("--codebase-path", type=str, default=".")
    parser.add_argument(
        "--backend",
        type=str,
        default="chroma",
        choices=["chroma", "postgres", "qdrant"],
    )
    parser.add_argument("--log-file", type=str)
    parser.add_argument(
        "--log-level",
        type=str.upper,
        choices=logging.getLevelNamesMapping(),
        default="ERROR",
    )
    parser.add_argument(
        "--log-workflow-debug",
        action="store_true",
        help="Emit a full local NDJSON workflow trace.",
    )
    parser.add_argument(
        "--log-workflow-debug-path",
        type=str,
        help="Directory or new .ndjson path for the workflow trace.",
    )
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
        help=(
            "Save analysis results to this file "
            "(repeatable, supports .json/.html/.csv/.sarif)"
        ),
    )
    parser.add_argument(
        "--output-files",
        nargs="+",
        help="Alternative syntax to provide multiple output files",
    )
    parser.add_argument(
        "--interactive", action="store_true", help="Run the interactive prompt"
    )
    parser.add_argument(
        "--triage",
        action="store_true",
        help=(
            "In the interactive prompt, triage findings after review commands "
            "and annotate SARIF output."
        ),
    )
    parser.add_argument(
        "--include-triaged",
        action="store_true",
        help="Include findings already triaged by Metis when running triage.",
    )
    parser.add_argument(
        "--tools",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()
    if args.tools is not None:
        parser.error(
            "--tools has been removed; configure execution nodes and capability grants in YAML"
        )
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
        COMMANDS["version"].invoke(
            None,
            [],
            args,
            CommandRuntime(
                command="version",
                command_args=[],
            ),
        )
        return
    try:
        if not check_dir_exists(args.codebase_path):
            raise SystemExit(1)
        configure_logger(logger, args)
        _run_cli(args)
    except (OSError, ValueError, YAMLError) as exc:
        print_console(f"[bold red]Error:[/bold red] {escape(str(exc))}", args.quiet)
        raise SystemExit(1) from None


def _run_cli(args):
    with workflow_debug_context(args) as runlog_session:
        if runlog_session is not None:
            args._metis_runlog = runlog_session
            print_console(
                f"[blue]Workflow debug log:[/blue] {runlog_session.ndjson_path}",
                args.quiet,
            )
        engine = None
        vector_backend = None
        exit_code = 0
        farewell = None
        try:
            runtime = load_runtime_config(
                config_path=args.config,
                enable_psql=(args.backend == "postgres"),
            )
            args._review_checkpoints_enabled = runtime.pop(
                "review_checkpoints_enabled", True
            )
            engine, vector_backend = build_engine(args, runtime)
            if not args.interactive:
                with runlog.span(
                    "command",
                    "execution_graph",
                    {"include_triaged": bool(args.include_triaged)},
                ) as command_span:
                    try:
                        determine_output_file("graph", args, [])
                        callbacks: dict[str, object] = {
                            "diagnostic_callback": (
                                lambda diagnostic: print_execution_diagnostic(
                                    diagnostic, args.quiet
                                )
                            )
                        }
                        callbacks.update(
                            review_checkpoint_callbacks(
                                codebase_path=args.codebase_path,
                                enabled=getattr(
                                    args, "_review_checkpoints_enabled", True
                                ),
                            )
                        )
                        result = _execute_graph_with_progress(
                            engine,
                            args,
                            callbacks,
                        )
                        _save_graph_outputs(
                            args.output_file,
                            result,
                            args.quiet,
                            generated_output=bool(
                                getattr(args, "_metis_generated_output", False)
                            ),
                        )
                    except Exception as exc:
                        partial = getattr(exc, "result", None)
                        if isinstance(partial, ExecutionResult) and partial.outputs:
                            try:
                                _save_graph_outputs(
                                    args.output_file,
                                    partial,
                                    args.quiet,
                                    generated_output=bool(
                                        getattr(args, "_metis_generated_output", False)
                                    ),
                                )
                            except Exception as save_error:
                                print_console(
                                    f"[red]Unable to save partial outputs: "
                                    f"{escape(str(save_error))}[/red]",
                                    args.quiet,
                                )
                        command_span.end(status="error", exc=exc)
                        print_console(
                            f"[bold red]Error:[/bold red] {escape(str(exc))}",
                            args.quiet,
                        )
                        exit_code = 1
                    else:
                        command_span.end(status=result.status.value)
                        if runlog_session is not None:
                            runlog_session.set_outcome(result.status.value)
                        if result.status is ExecutionStatus.OK:
                            print_console(
                                "[green]Execution graph complete.[/green]", args.quiet
                            )
                        elif result.status is ExecutionStatus.INCONCLUSIVE:
                            print_console(
                                "[yellow]Execution graph finished with inconclusive results.[/yellow]",
                                args.quiet,
                            )
                        else:
                            print_console(
                                "[red]Execution graph failed.[/red]", args.quiet
                            )
                            exit_code = 1
            else:
                farewell = run_interactive_loop(engine, args, vector_backend)
        finally:
            if engine is not None:
                finalize_cli_session_and_close(engine, args, farewell)
        if exit_code:
            if runlog_session is not None:
                runlog_session.set_outcome("error")
            raise SystemExit(exit_code)
