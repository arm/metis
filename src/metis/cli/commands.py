# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from importlib.metadata import version as package_version
import json
from pathlib import Path
from rich.markup import escape

from metis.runtime_settings import TriageOptions
from .command_runtime import CommandRuntime
from .review_progress import ReviewCodeProgressReporter
from metis.utils import read_file_content, safe_decode_unicode
from metis.sarif.writer import generate_sarif
from metis.sarif.triage import load_sarif_file
from metis.usage import usage_operation
from .triage_cli import run_triage_action
from .utils import (
    check_dir_exists,
    check_file_exists,
    build_standard_progress,
    with_spinner,
    with_timer,
    iterate_with_progress,
    count_index_items,
    pretty_print_reviews,
    save_output,
    print_console,
    output_format,
    output_files_for_formats,
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
    if not check_file_exists(patch_file):
        return
    return _run_review_command(
        engine,
        "patch",
        patch_file,
        args,
        "Reviewing patch...",
    )


def run_file_review(engine, file_path, args, runtime: CommandRuntime):
    if not check_file_exists(file_path):
        return
    return _run_review_command(
        engine,
        "file",
        file_path,
        args,
        f"Reviewing file {file_path}...",
    )


def run_dir_review(engine, dir_path, args, runtime: CommandRuntime):
    review_dir_path = str(Path(engine.codebase_path) / dir_path)
    if not check_dir_exists(review_dir_path):
        return
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
    outputs = _execute_review(
        engine,
        mode,
        target,
        args,
        spinner_text,
    )
    results = outputs["findings"]
    sarif_output = outputs["sarif"]
    formats = tuple(outputs["formats"])
    if getattr(args, "triage", False):
        triage = _triage_review_output(
            engine,
            sarif_output,
            outputs.get("codegraph"),
            args,
        )
        if triage is not None:
            sarif_output = triage["sarif"]
            formats = tuple(dict.fromkeys((*formats, *triage["formats"])))
    generated_output = bool(getattr(args, "_metis_generated_output", False))
    if not generated_output:
        explicit_formats = tuple(output_format(path) for path in args.output_file or ())
        formats = tuple(dict.fromkeys((*formats, *explicit_formats)))
    args.output_file = output_files_for_formats(
        args.output_file,
        formats,
        command=f"review_{mode}",
        generated_output=generated_output,
    )
    _finalize_review_output(
        results,
        args,
        sarif_payload=sarif_output,
    )


def _execute_review(engine, mode, target, args, spinner_text):
    kwargs = {
        "target": target,
        "callbacks": {
            "diagnostic_callback": lambda diagnostic: _print_review_diagnostic(
                diagnostic,
                args.quiet,
            )
        },
    }
    if mode not in {"code", "dir"} or args.quiet:
        return with_spinner(
            spinner_text,
            engine.execute_review,
            mode,
            **kwargs,
            quiet=args.quiet,
        )

    with build_standard_progress(transient=True) as progress:
        reporter = ReviewCodeProgressReporter(progress, total_files=0)
        try:
            return engine.execute_review(
                mode,
                target=target,
                callbacks={
                    "progress_callback": reporter,
                    "diagnostic_callback": lambda diagnostic: _print_review_diagnostic(
                        diagnostic, args.quiet
                    ),
                },
            )
        finally:
            reporter.finish()


def _print_review_diagnostic(diagnostic, quiet):
    color = "yellow" if diagnostic.severity == "warning" else "red"
    print_console(
        f"[{color}]{escape(diagnostic.message)}[/{color}]",
        quiet,
    )


def _triage_review_output(engine, sarif_payload, codegraph, args):
    options = _triage_options(args)

    def _invoke(debug_callback=None, progress_callback=None):
        return engine.execute_triage(
            sarif_payload,
            codegraph=codegraph,
            options=options,
            debug_callback=debug_callback,
            progress_callback=progress_callback,
        )

    try:
        with usage_operation("triage"):
            return run_triage_action(
                args,
                action=_invoke,
                spinner_text="Triaging findings...",
            )
    except Exception as exc:
        print_console(
            f"[yellow]Triage skipped due to error: {escape(str(exc))}[/yellow]",
            args.quiet,
        )
        return None


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
    save_output(args.output_file, results, args.quiet)


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
    save_output(args.output_file, answer, args.quiet)


def run_triage(engine, findings_path, args, runtime: CommandRuntime):
    if not check_file_exists(findings_path, quiet=args.quiet):
        return
    suffix = Path(findings_path).suffix.lower()
    if suffix == ".json":
        return _run_json_triage(engine, findings_path, args, runtime)
    if suffix != ".sarif":
        print_console(
            "[red]Only .sarif and Metis .json input files are supported.[/red]",
            args.quiet,
        )
        return
    print_console("[cyan]Loading SARIF findings...[/cyan]", args.quiet)
    options = _triage_options(args)
    sarif_payload = load_sarif_file(findings_path)
    requested_outputs = list(args.output_file or ())
    checkpoint_path = next(
        (path for path in requested_outputs if Path(path).suffix.lower() == ".sarif"),
        str(Path(requested_outputs[0]).with_suffix(".sarif"))
        if requested_outputs
        else findings_path,
    )

    def _invoke(debug_callback=None, progress_callback=None):
        return engine.execute_triage(
            sarif_payload,
            options=options,
            debug_callback=debug_callback,
            progress_callback=progress_callback,
            checkpoint_path=checkpoint_path,
        )

    triage = run_triage_action(
        args,
        action=_invoke,
        spinner_text="Triaging SARIF findings...",
    )
    output_files = output_files_for_formats(
        args.output_file or [findings_path],
        tuple(triage["formats"]),
        command="triage",
        generated_output=args.output_file is None,
    )
    save_output(
        output_files,
        triage["sarif"],
        args.quiet,
        sarif_payload=triage["sarif"],
    )
    print_console("[green]Triage complete.[/green]", args.quiet)


def _run_json_triage(engine, json_path, args, runtime: CommandRuntime):
    print_console("[cyan]Loading Metis JSON findings...[/cyan]", args.quiet)
    with Path(json_path).open("r", encoding="utf-8") as f:
        results = json.load(f)
    if not isinstance(results, dict) or not isinstance(results.get("reviews"), list):
        print_console(
            "[red]JSON input must be a Metis results object with a reviews array.[/red]",
            args.quiet,
        )
        return

    options = _triage_options(args)
    sarif_payload = generate_sarif(results)

    def _invoke(debug_callback=None, progress_callback=None):
        return engine.execute_triage(
            sarif_payload,
            options=options,
            debug_callback=debug_callback,
            progress_callback=progress_callback,
        )

    triage = run_triage_action(
        args,
        action=_invoke,
        spinner_text="Triaging JSON findings...",
    )

    output_files = output_files_for_formats(
        args.output_file or [json_path],
        tuple(triage["formats"]),
        command="triage",
        generated_output=args.output_file is None,
    )
    save_output(
        output_files,
        results,
        args.quiet,
        sarif_payload=triage["sarif"],
    )
    print_console("[green]Triage complete.[/green]", args.quiet)


def _finalize_review_output(
    results,
    args,
    *,
    sarif_payload,
):
    pretty_print_reviews(results, args.quiet)
    save_output(args.output_file, results, args.quiet, sarif_payload=sarif_payload)
