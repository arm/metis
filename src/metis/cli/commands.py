# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import functools
from importlib.metadata import version as package_version
import json
from pathlib import Path
from rich.markup import escape

from metis.engine.execution import ExecutionResult
from metis.json_io import json_object_from_pairs
from metis.runtime_settings import TriageOptions
from .command_runtime import CommandRuntime
from .output import save_graph_outputs
from .output import output_files_for_formats
from .output import output_format
from .output import save_output
from .review_checkpoints import review_checkpoint_callbacks
from .review_progress import ReviewCodeProgressReporter
from metis.utils import read_file_content, safe_decode_unicode
from metis.utils import resolve_path_within_root
from metis.sarif.writer import generate_sarif
from metis.sarif.triage import load_sarif_file
from metis.usage import usage_operation
from .triage_cli import run_triage_action
from .triage_checkpoints import triage_checkpoint_path
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
    pending_error = None
    try:
        outputs = _execute_review(engine, mode, target, args, spinner_text)
    except BaseException as execution_error:
        partial = getattr(execution_error, "result", None)
        outputs = (
            partial.outputs.get("review")
            if isinstance(partial, ExecutionResult)
            else None
        )
        if outputs is None or (
            outputs.get("findings") is None and outputs.get("sarif") is None
        ):
            raise
        pending_error = execution_error
    outputs = dict(outputs)
    sarif_output = outputs.get("sarif")
    formats = tuple(outputs.get("formats", ()))
    if pending_error is None and getattr(args, "triage", False):
        try:
            triage = _triage_review_output(
                engine,
                sarif_output,
                outputs.get("codegraph"),
                args,
                filename=outputs.get("filename"),
                formats=formats,
                mode=mode,
            )
        except BaseException as triage_error:
            pending_error = triage_error
            partial = getattr(triage_error, "result", None)
            triage = (
                partial.outputs.get("triage", {})
                if isinstance(partial, ExecutionResult)
                else {}
            )
        if triage.get("sarif") is not None:
            sarif_output = triage["sarif"]
            formats = tuple(dict.fromkeys((*formats, *triage.get("formats", ()))))
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


def _execute_review(engine, mode, target, args, spinner_text):
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
            return engine.execute_review(
                mode,
                target=target,
                callbacks=callbacks,
            )
        finally:
            reporter.finish()


def _triage_review_output(
    engine, sarif_payload, codegraph, args, *, filename, formats, mode
):
    options = _triage_options(args)
    generated_output = (
        bool(getattr(args, "_metis_generated_output", False)) or not args.output_file
    )
    selected = (
        [filename] if generated_output and filename is not None else args.output_file
    )
    if not selected:
        selected = output_files_for_formats(
            None, ("sarif",), command=f"review_{mode}", generated_output=True
        )
        args.output_file = selected
        args._metis_generated_output = True
    explicit_formats = (
        () if generated_output else tuple(output_format(path) for path in selected)
    )
    paths = output_files_for_formats(
        selected,
        tuple(dict.fromkeys((*formats, *explicit_formats))),
        command=f"review_{mode}",
        generated_output=generated_output,
    )
    checkpoint_path = (
        triage_checkpoint_path(paths or selected, reserved_paths=paths)
        if getattr(args, "_triage_checkpoint_every", 50) > 0
        else None
    )

    with usage_operation("triage"):
        return run_triage_action(
            args,
            action=functools.partial(
                engine.execute_triage,
                sarif_payload,
                codegraph=codegraph,
                options=options,
                checkpoint_path=str(checkpoint_path)
                if checkpoint_path is not None
                else None,
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
    results = None
    if suffix == ".json":
        print_console("[cyan]Loading JSON findings...[/cyan]", args.quiet)
        with Path(findings_path).open("r", encoding="utf-8") as source:
            payload = json.load(source, object_pairs_hook=json_object_from_pairs)
        if isinstance(payload, dict) and isinstance(payload.get("reviews"), list):
            results = payload
            sarif_payload = generate_sarif(results, read_source=False)
        elif isinstance(payload, dict) and isinstance(payload.get("runs"), list):
            sarif_payload = payload
        else:
            raise ValueError(
                "JSON input must contain a Metis reviews array or a SARIF runs array."
            )
    elif suffix == ".sarif":
        print_console("[cyan]Loading SARIF findings...[/cyan]", args.quiet)
        sarif_payload = load_sarif_file(findings_path)
    else:
        raise ValueError("Only .sarif and .json input files are supported.")
    options = _triage_options(args)
    requested_outputs = list(args.output_file or ())
    configured_filename = None
    configured_formats = ()
    execution = getattr(engine, "execution", None)
    if not requested_outputs and execution is not None:
        stage = execution.configuration.stages.triage
        if stage is not None:
            for node in stage.nodes.values():
                if node.filename is not None:
                    configured_filename = node.filename
                    configured_formats = node.formats or ()
                    requested_outputs = [configured_filename]
                    break
    checkpoint_path = next(
        (path for path in requested_outputs if Path(path).suffix.lower() == ".sarif"),
        str(Path(requested_outputs[0]).with_suffix(".sarif"))
        if requested_outputs
        else str(Path(findings_path).with_suffix(".sarif"))
        if suffix == ".json"
        else findings_path,
    )

    pending_error = None
    try:
        triage = run_triage_action(
            args,
            action=functools.partial(
                engine.execute_triage,
                sarif_payload,
                options=options,
                checkpoint_path=checkpoint_path,
            ),
            spinner_text="Triaging findings...",
        )
    except BaseException as exc:
        partial = getattr(exc, "result", None)
        if not isinstance(partial, ExecutionResult):
            raise
        triage = partial.outputs.get("triage", {})
        if triage.get("sarif") is None:
            raise
        pending_error = exc
    selected_outputs = args.output_file
    filename = triage.get("filename") or configured_filename
    if not selected_outputs and filename is None:
        selected_outputs = [findings_path]
    save_graph_outputs(
        selected_outputs,
        {
            "triage": {
                **triage,
                "findings": results,
                "filename": filename,
                "formats": triage.get("formats", configured_formats),
            }
        },
        args.quiet,
        generated_output=not selected_outputs,
        codebase_path=getattr(engine, "codebase_path", None),
        pending_error=pending_error,
        command="triage",
    )
    print_console("[green]Triage complete.[/green]", args.quiet)
