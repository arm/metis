# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import argparse
from concurrent.futures import CancelledError
from copy import copy
from datetime import datetime
import logging
from pathlib import Path
import shlex
from tempfile import TemporaryDirectory
from typing import Any
from typing import cast
from uuid import uuid4

from rich.markup import escape
from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from yaml import YAMLError

from metis.configuration import build_embedding_provider_config
from metis.configuration import load_execution_config
from metis.configuration import load_runtime_config
from metis.engine import MetisEngine
from metis.engine.execution import ExecutionResult
from metis.engine.execution import ExecutionStatus
from metis.engine.stages.configuration import ExecutionConfiguration
from metis.engine.stages.review.models import REVIEW_FAILURE_CODES
from metis.engine.stages.triage.models import TRIAGE_FINDING_FAILED
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
from .review_checkpoints import stage_checkpoint_callback
from .review_progress import ExecutionGraphProgressReporter
from .output import graph_output_files
from .output import save_graph_outputs
from .output import streaming_output_files
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
    *,
    export_directory,
    generated_bases=None,
) -> ExecutionResult:
    kwargs = {"include_triaged": True if args.include_triaged else None}
    output_files = args.output_file
    stages = engine.execution._stages
    planned = {}
    for name in ("review", "triage"):
        stage = stages.get(name)
        if stage is None or "result" not in stage.nodes:
            continue
        node = stage.nodes["result"]
        planned[name] = {
            "formats": node.formats or (),
            "filename": node.filename,
            "sarif": {},
            **({"findings": {}} if name == "review" else {}),
        }
    paths = (
        graph_output_files(
            output_files,
            planned,
            args.quiet,
            generated_output=bool(getattr(args, "_metis_generated_output", False)),
            generated_bases=generated_bases,
        )
        if planned
        else {"review": [], "triage": []}
    )
    destinations = streaming_output_files(paths, export_directory)
    kwargs.update(
        output_path=destinations["review"],
        triage_output_path=destinations["triage"],
    )
    if not args.verbose:
        return engine.execute_graph(callbacks=callbacks, **kwargs)

    with build_standard_progress(transient=True) as progress:
        reporter = ExecutionGraphProgressReporter(progress)
        callbacks["progress_callback"] = reporter
        try:
            return engine.execute_graph(callbacks=callbacks, **kwargs)
        finally:
            reporter.finish()


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
    execution = ExecutionConfiguration.model_validate(
        load_execution_config(runtime.get("execution_config"))
    )
    engine_runtime["execution_config"] = execution
    engine_runtime.pop("review_checkpoints_enabled", None)
    if "index" in execution.selected_capabilities():
        embedding_provider_config = build_embedding_provider_config(
            cast(dict | None, runtime.get("embedding_provider_raw_config"))
        )
        if embedding_provider_config is not None:
            embedding_provider_cls = get_embedding_provider(
                str(embedding_provider_config["name"])
            )
            embedding_provider = embedding_provider_cls(
                cast(dict, embedding_provider_config)
            )
    llm_provider = chat_provider_cls(cast(dict, runtime["llm_provider"]))
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
        except CancelledError:
            raise
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
        help="Path to a Metis config file (default: packaged configuration; no repository config discovery).",
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
    args.codebase_path = str(Path(args.codebase_path).absolute())
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
            args._review_checkpoints_enabled = runtime.get(
                "review_checkpoints_enabled", True
            )
            engine, vector_backend = build_engine(args, runtime)
            if not args.interactive:
                execution = engine.execution.configuration
                triage_stage = execution.stages.triage
                triage_from_review = (
                    triage_stage is not None
                    and triage_stage.inputs.get("sarif") == "review.sarif"
                )
                with (
                    TemporaryDirectory(prefix="metis-export-") as export_directory,
                    runlog.span(
                        "command",
                        "execution_graph",
                        {"include_triaged": bool(args.include_triaged)},
                    ) as command_span,
                ):
                    generated_bases: dict[str, str] = {}
                    try:
                        determine_output_file("graph", args, [])
                        callbacks: dict[str, object] = {
                            "diagnostic_callback": (
                                lambda diagnostic: print_execution_diagnostic(
                                    diagnostic, args.quiet
                                )
                            )
                        }
                        if args._review_checkpoints_enabled:
                            callbacks["stage_completed_callback"] = (
                                stage_checkpoint_callback(
                                    codebase_path=args.codebase_path,
                                )
                            )
                        callbacks.update(
                            review_checkpoint_callbacks(
                                codebase_path=args.codebase_path,
                                enabled=getattr(
                                    args, "_review_checkpoints_enabled", True
                                ),
                            )
                        )
                        pending_error = None
                        try:
                            result = _execute_graph_with_progress(
                                engine,
                                args,
                                callbacks,
                                export_directory=export_directory,
                                generated_bases=generated_bases,
                            )
                        except CancelledError:
                            raise
                        except Exception as execution_error:
                            result = getattr(execution_error, "result", None)
                            if (
                                not isinstance(result, ExecutionResult)
                                or not result.outputs
                            ):
                                raise
                            pending_error = execution_error
                        save_graph_outputs(
                            args.output_file,
                            result.outputs,
                            args.quiet,
                            generated_output=bool(
                                getattr(args, "_metis_generated_output", False)
                            ),
                            triage_from_review=triage_from_review,
                            generated_bases=generated_bases,
                            codebase_path=args.codebase_path,
                            partial=result.status is ExecutionStatus.ERROR,
                            pending_error=pending_error,
                        )
                        if any(
                            diagnostic.code in REVIEW_FAILURE_CODES
                            for diagnostic in result.diagnostics
                        ):
                            raise RuntimeError("Review failed for one or more files.")
                        if any(
                            diagnostic.code == TRIAGE_FINDING_FAILED
                            for diagnostic in result.diagnostics
                        ):
                            raise RuntimeError(
                                "Triage failed for one or more findings."
                            )
                    except CancelledError:
                        raise
                    except Exception as exc:
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
