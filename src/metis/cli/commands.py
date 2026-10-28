# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import functools
from contextlib import nullcontext
from importlib.metadata import version as package_version
from pathlib import Path
from tempfile import TemporaryDirectory
from rich.markup import escape

from metis.engine.execution import ExecutionResult
from metis.engine.nodes.builtins import streaming_stages
from metis.json_io import load_json_object_file
from metis.runtime_settings import TriageOptions
from .command_runtime import CommandRuntime
from .output import save_graph_outputs
from .output import graph_output_files
from .output import output_format
from .output import save_output
from .output import streaming_output_files
from .review_checkpoints import review_checkpoint_callbacks
from .review_progress import ReviewCodeProgressReporter
from metis.utils import read_file_content, safe_decode_unicode
from metis.utils import resolve_path_within_root
from metis.sarif.writer import generate_sarif
from metis.sarif.triage import load_sarif_file
from metis.usage import usage_operation
from .triage_cli import run_triage_action
from .utils import (
    check_file_exists,
    build_standard_progress,
    with_spinner,
    with_timer,
    iterate_with_progress,
    count_index_items,
    print_console,
    print_execution_diagnostic,
)


def _triage_options(args) -> TriageOptions | None:
    if not bool(getattr(args, "include_triaged", False)):
        return None
    return TriageOptions(include_triaged=True)


def show_help(args=None):
    print_console(
        """
[bold blue]Metis CLI[/bold blue]

Type one of the following commands (with arguments):

- [cyan]index[/cyan]
- [cyan]init[/cyan]
- [cyan]review_patch mypatch.diff[/cyan]
- [cyan]review_dir path_to_dir[/cyan]
- [cyan]review_file path_to_file/myfile.c[/cyan]
- [cyan]review_code[/cyan]
- [cyan]triage findings.sarif[/cyan] or [cyan]triage results.json[/cyan]
- [cyan]update patch.diff[/cyan]
- [cyan]ask "Give me an overview of the code"[/cyan]
- [magenta]exit[/magenta]   (quit the tool)
- [magenta]help[/magenta]   (show this message)

Options:
    --backend chroma|postgres|qdrant  Vector backend to use (default: chroma).
    --output-file PATH         Save analysis results to this file.
    --custom-prompt PATH       Custom prompt file (.md or .txt) to guide analysis.
    --triage                   Triage findings and annotate SARIF output for review commands.
    --include-triaged          Include findings already triaged by Metis.
    --project-schema SCHEMA    (Optional) Project identifier if postgresql is used.
    --chroma-dir DIR           (Optional) Directory to store ChromaDB data (default: ./chromadb).
    --qdrant-url URL           (Optional) Qdrant server URL (default: http://localhost:6333).
    --verbose                  (Optional) Shows detailed output in the terminal window.
    --version                  (Optional) Show program version
"""
    )


def show_version(args=None):
    version = package_version("metis")
    print_console("Metis [green]" + version + "[/green]")


def run_review(engine, patch_file, args, runtime: CommandRuntime):
    if not Path(patch_file).is_file():
        raise FileNotFoundError(f"Patch file not found: {patch_file}")
    return _run_review_command(
        engine,
        "patch",
        patch_file,
        args,
        "Reviewing patch...",
    )


def run_file_review(engine, file_path, args, runtime: CommandRuntime):
    review_file_path = str(Path(engine.codebase_path).absolute() / file_path)
    resolve_path_within_root(engine.codebase_path, review_file_path)
    if not Path(review_file_path).is_file():
        raise FileNotFoundError(f"Review file not found: {review_file_path}")
    return _run_review_command(
        engine,
        "file",
        review_file_path,
        args,
        f"Reviewing file {file_path}...",
    )


def run_dir_review(engine, dir_path, args, runtime: CommandRuntime):
    review_dir_path = str(Path(engine.codebase_path).absolute() / dir_path)
    resolve_path_within_root(engine.codebase_path, review_dir_path)
    if not Path(review_dir_path).is_dir():
        raise NotADirectoryError(f"Review directory not found: {review_dir_path}")
    return _run_review_command(
        engine,
        "dir",
        review_dir_path,
        args,
        "Reviewing directory...",
    )


def run_review_code(engine, args, runtime: CommandRuntime):
    return _run_review_command(
        engine,
        "code",
        None,
        args,
        "Reviewing codebase...",
    )


def _run_review_command(engine, mode, target, args, spinner_text):
    with TemporaryDirectory(prefix="metis-review-") as export_directory:
        pending_error = None
        try:
            outputs = _execute_review(
                engine,
                mode,
                target,
                args,
                spinner_text,
                export_directory=export_directory,
            )
        except BaseException as execution_error:
            partial = getattr(execution_error, "result", None)
            outputs = (
                partial.outputs.get("review")
                if isinstance(partial, ExecutionResult)
                else None
            )
            if outputs is None or not any(
                outputs.get(name) is not None
                for name in ("findings", "sarif", "json_path", "sarif_path")
            ):
                raise
            pending_error = execution_error
        outputs = dict(outputs)
        sarif_output = outputs.get("sarif")
        formats = tuple(outputs.get("formats", ()))
        if pending_error is None and getattr(args, "triage", False):
            try:
                triage = _triage_review_output(engine, outputs, args)
            except BaseException as triage_error:
                pending_error = triage_error
                partial = getattr(triage_error, "result", None)
                triage = (
                    partial.outputs.get("triage", {})
                    if isinstance(partial, ExecutionResult)
                    else {}
                )
            if triage:
                sarif_output = triage.get("sarif", sarif_output)
                formats = tuple(dict.fromkeys((*formats, *triage.get("formats", ()))))
                outputs.update(
                    {
                        name: value
                        for name, value in triage.items()
                        if name in {"json_path", "sarif_path"}
                    }
                )
        outputs.update(formats=formats, sarif=sarif_output)
        args.output_file = save_graph_outputs(
            args.output_file,
            {"review": outputs},
            args.quiet,
            generated_output=bool(getattr(args, "_metis_generated_output", False)),
            codebase_path=getattr(engine, "codebase_path", None),
            pending_error=pending_error,
            command="review",
        )["review"]


def _execute_review(
    engine,
    mode,
    target,
    args,
    spinner_text,
    *,
    export_directory,
):
    callbacks = {
        "diagnostic_callback": lambda diagnostic: print_execution_diagnostic(
            diagnostic,
            args.quiet,
        )
    }
    callbacks.update(
        review_checkpoint_callbacks(
            codebase_path=getattr(engine, "codebase_path", "."),
            enabled=getattr(args, "_review_checkpoints_enabled", True),
        )
    )
    kwargs = {
        "target": target,
        "callbacks": callbacks,
    }
    result_node = engine.execution._stages["review"].nodes.get("result")
    if result_node is not None and (
        not getattr(args, "triage", False)
        or "triage" in streaming_stages(engine.execution._stages, "triage")
    ):
        result_formats = (
            result_node.formats
            or tuple(
                dict.fromkeys(output_format(path) for path in args.output_file or ())
            )
            or ("json",)
        )
        generated = (
            bool(getattr(args, "_metis_generated_output", False))
            or not args.output_file
        )
        filename = result_node.filename
        if generated and filename is None and args.output_file:
            filename = args.output_file[0]
        paths = graph_output_files(
            args.output_file,
            {
                "review": {
                    "formats": result_formats,
                    "filename": filename,
                    "findings": {},
                    "sarif": {},
                }
            },
            args.quiet,
            generated_output=generated,
        )["review"]
        args.output_file = paths
        args._metis_generated_output = False
        kwargs["output_path"] = streaming_output_files(
            {"review": paths}, export_directory
        )["review"]
    if mode not in {"code", "dir"} or args.quiet:
        return with_spinner(
            spinner_text,
            engine.execute_review,
            mode,
            **kwargs,
            quiet=args.quiet,
        )

    with build_standard_progress(transient=False) as progress:
        reporter = ReviewCodeProgressReporter(progress)
        try:
            callbacks["progress_callback"] = reporter
            return engine.execute_review(mode, **kwargs)
        finally:
            reporter.finish()


def _triage_review_output(engine, outputs, args):
    options = _triage_options(args)
    source_path = outputs.get("json_path") or outputs.get("sarif_path")
    action = (
        functools.partial(engine.execute_triage_file, source_path, source_path)
        if source_path is not None
        else functools.partial(engine.execute_triage, outputs.get("sarif"))
    )
    with usage_operation("triage"):
        return run_triage_action(
            args,
            action=functools.partial(
                action,
                codegraph=outputs.get("codegraph"),
                options=options,
            ),
            spinner_text="Triaging findings...",
        )


def run_init(engine, args, runtime: CommandRuntime):
    results = with_spinner(
        "Initializing codebase context...",
        engine.init_codebase,
        quiet=args.quiet,
    )
    threat_model = results.get("threat_model")
    index_status = results.get("index")
    if threat_model is not None:
        source_text = ", ".join(threat_model["authoritative_sources"]) or "none"
        print_console(
            "[green]Threat model initialized.[/green] "
            f"Records: {threat_model['records_written']}; "
            f"authoritative sources: {escape(source_text)}",
            args.quiet,
        )
    if index_status is not None:
        print_console(
            f"[green]Index status:[/green] {escape(index_status['status'])}",
            args.quiet,
        )
    save_output(
        args.output_file,
        results,
        args.quiet,
        codebase_path=getattr(engine, "codebase_path", None),
    )


def run_index(engine, verbose=False, quiet=False):
    if verbose:
        print_console("[cyan]Indexing codebase...[/cyan]", quiet)
        total = count_index_items(engine)
        if total > 0:
            iterate_with_progress(total, engine.indexing.index_prepare_nodes_iter())
            with_timer(
                "Embedding indexes...",
                engine.indexing.index_finalize_embeddings,
                quiet=quiet,
            )
            print_console("[green]Indexing completed successfully.[/green]", quiet)
            return

    with_spinner("Indexing codebase...", engine.indexing.index_codebase, quiet=quiet)
    print_console("[green]Indexing completed successfully.[/green]", quiet)


def run_update(engine, patch_file, args, runtime: CommandRuntime):
    if not check_file_exists(patch_file):
        return
    file_diff = read_file_content(patch_file)
    with_spinner(
        "Updating index...",
        engine.indexing.update_index,
        file_diff,
        quiet=args.quiet,
    )
    print_console("[green]Index update completed.[/green]", args.quiet)


def run_ask(engine, question, args, runtime: CommandRuntime):
    answer = with_spinner(
        "Thinking...", engine.ask_question, question, quiet=args.quiet
    )
    print_console("[bold magenta]Metis Answer:[/bold magenta]\n")
    if isinstance(answer, dict):
        if "code" in answer:
            print_console(
                f"[bold yellow]Code Context:[/bold yellow] {escape(safe_decode_unicode(answer['code']))} \n",
            )
        if "docs" in answer:
            print_console(
                f"[bold blue]Documentation Context:[/bold blue] {escape(safe_decode_unicode(answer['docs']))}",
            )
    else:
        print_console(escape(str(answer)))
    save_output(
        args.output_file,
        answer,
        args.quiet,
        codebase_path=getattr(engine, "codebase_path", None),
    )


def run_triage(engine, findings_path, args, runtime: CommandRuntime):
    if not Path(findings_path).is_file():
        raise FileNotFoundError(f"File not found: {findings_path}")
    suffix = Path(findings_path).suffix.lower()
    if suffix not in {".json", ".sarif"}:
        raise ValueError("Only .sarif and .json input files are supported.")
    stage = engine.execution._stages.get("triage")
    nodes = stage.nodes if stage is not None else {}
    result_node = next(
        (node for node in nodes.values() if node.filename is not None),
        nodes.get("result"),
    )
    filename = getattr(result_node, "filename", None)
    formats = tuple(getattr(result_node, "formats", None) or ())
    streaming = "triage" in streaming_stages(engine.execution._stages, "triage")
    if not formats and args.output_file:
        formats = tuple(dict.fromkeys(output_format(path) for path in args.output_file))
    if streaming and not formats and filename is None:
        formats = ("sarif",)
    paths = (
        graph_output_files(
            args.output_file or ([findings_path] if filename is None else None),
            {
                "triage": {
                    "formats": formats,
                    "filename": filename,
                    "sarif_path": findings_path,
                }
            },
            args.quiet,
            generated_output=not args.output_file and filename is not None,
        )["triage"]
        if streaming
        else []
    )
    destination = next(
        (
            path
            for path in paths
            if output_format(path)
            in ({"json"} if suffix == ".json" else {"json", "sarif"})
        ),
        None,
    )
    temporary = (
        TemporaryDirectory(prefix="metis-triage-")
        if streaming and destination is None
        else nullcontext()
    )
    with temporary as directory:
        if directory is not None:
            destination = Path(directory) / "triage.json"
        results = None
        if streaming:
            action = functools.partial(
                engine.execute_triage_file, findings_path, destination
            )
        else:
            if suffix == ".json":
                payload = load_json_object_file(findings_path)
                if isinstance(payload.get("reviews"), list):
                    results = payload
                    payload = generate_sarif(results, read_source=False)
                elif not isinstance(payload.get("runs"), list):
                    raise ValueError(
                        "JSON input must contain a Metis reviews array or a SARIF runs array."
                    )
            else:
                payload = load_sarif_file(findings_path)
            action = functools.partial(engine.execute_triage, payload)
        pending_error = None
        try:
            triage = run_triage_action(
                args,
                action=functools.partial(
                    action,
                    options=_triage_options(args),
                ),
                spinner_text="Triaging findings...",
            )
        except BaseException as exc:
            partial = getattr(exc, "result", None)
            if not isinstance(partial, ExecutionResult):
                raise
            triage = partial.outputs.get("triage", {})
            if not any(
                triage.get(name) is not None
                for name in ("sarif", "json_path", "sarif_path")
            ):
                raise
            pending_error = exc
        filename = triage.get("filename") or filename
        selected_outputs = paths if streaming else args.output_file
        if not selected_outputs and filename is None:
            selected_outputs = [findings_path]
        save_graph_outputs(
            selected_outputs,
            {
                "triage": {
                    **triage,
                    "findings": results,
                    "formats": triage.get("formats", formats),
                    "filename": filename,
                }
            },
            args.quiet,
            generated_output=not selected_outputs,
            codebase_path=getattr(engine, "codebase_path", None),
            pending_error=pending_error,
            command="triage",
        )
    print_console("[green]Triage complete.[/green]", args.quiet)
