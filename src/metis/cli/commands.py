# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


from importlib.metadata import version as package_version
import inspect
import json
from pathlib import Path
from rich.markup import escape

from metis.engine.options import TriageOptions
from .command_runtime import CommandRuntime
from .review_progress import ReviewCodeProgressReporter
from metis.utils import read_file_content, safe_decode_unicode
from metis.sarif.writer import generate_sarif
from metis.usage import usage_operation
from .triage_cli import run_triage_action
from .utils import (
    check_dir_exists,
    check_file_exists,
    with_spinner,
    with_timer,
    collect_reviews,
    iterate_with_progress,
    build_standard_progress,
    count_index_items,
    pretty_print_reviews,
    save_output,
    print_console,
)


def _triage_options_for_runtime(args, runtime: CommandRuntime) -> TriageOptions:
    return TriageOptions(
        include_triaged=bool(getattr(args, "include_triaged", False)),
    )


def show_help(args=None):
    print_console(
        """
[bold blue]Metis CLI[/bold blue]

Type one of the following commands (with arguments):

- [cyan]index[/cyan]
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
    --backend chroma|postgres  Vector backend to use (default: chroma).
    --output-file PATH         Save analysis results to this file.
    --custom-prompt PATH       Custom prompt file (.md or .txt) to guide analysis.
    --triage                   Triage findings and annotate SARIF output for review commands.
    --include-triaged          Include findings already triaged by Metis.
    --tools index,navigation|all|none
                               Enable optional engine tools.
    --project-schema SCHEMA    (Optional) Project identifier if postgresql is used.
    --chroma-dir DIR           (Optional) Directory to store ChromaDB data (default: ./chromadb).
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
    results = with_spinner(
        "Reviewing patch...",
        engine.review.review_patch,
        patch_file=patch_file,
        quiet=args.quiet,
    )
    _finalize_review_output(engine, results, args, runtime)


def run_file_review(engine, file_path, args, runtime: CommandRuntime):
    if not check_file_exists(file_path):
        return
    raw_result = with_spinner(
        f"Reviewing file {file_path}...",
        engine.review.review_file,
        file_path=file_path,
        quiet=args.quiet,
    )

    if raw_result and isinstance(raw_result.get("reviews"), list):
        results = {"reviews": [raw_result]}
    else:
        results = {"reviews": []}

    _finalize_review_output(engine, results, args, runtime)


def run_dir_review(engine, dir_path, args, runtime: CommandRuntime):
    review_dir_path = str(Path(engine.codebase_path) / dir_path)
    if not check_dir_exists(review_dir_path):
        return
    code_files = list(engine.review.get_code_files(dir_path=review_dir_path))
    _review_code(engine, code_files, args, runtime)


def run_review_code(engine, args, runtime: CommandRuntime):
    code_files = list(engine.review.get_code_files())
    _review_code(engine, code_files, args, runtime)


def _review_code(engine, code_files, args, runtime: CommandRuntime):
    if not args.quiet:
        file_reviews = _collect_review_code_with_progress(
            engine,
            code_files,
        )
        results = {"reviews": file_reviews}
    elif args.verbose:
        file_reviews = iterate_with_progress(
            len(code_files),
            _review_code_iter(engine.review, code_files=code_files),
        )
        results = {"reviews": file_reviews}
    else:
        results = with_spinner(
            "Reviewing codebase...",
            collect_reviews,
            engine,
            kwargs=_get_review_code_kargs(
                engine.review.review_code, code_files=code_files
            ),
            quiet=args.quiet,
        )
    _finalize_review_output(engine, results, args, runtime)


def _collect_review_code_with_progress(engine, code_files):
    results = []
    total = len(code_files)
    with build_standard_progress(transient=True) as progress:
        progress_reporter = ReviewCodeProgressReporter(
            progress,
            total_files=total,
        )
        for item in _review_code_iter(
            engine.review,
            progress_callback=progress_reporter,
            code_files=code_files,
        ):
            if item is not None:
                results.append(item)
            progress_reporter.review_result()
        progress_reporter.finish()
    return results


def _get_review_code_kargs(
    review_code, progress_callback=None, code_files=None
) -> dict:
    kwargs = {}
    try:
        signature = inspect.signature(review_code)
    except (TypeError, ValueError):
        signature = None
    if signature is not None:
        params = signature.parameters
        accepts_kwargs = any(
            param.kind == inspect.Parameter.VAR_KEYWORD for param in params.values()
        )
        if progress_callback is not None and (
            "progress_callback" in params or accepts_kwargs
        ):
            kwargs["progress_callback"] = progress_callback
        if code_files is not None and (
            "get_code_files_func" in params or accepts_kwargs
        ):
            kwargs["get_code_files_func"] = lambda: code_files
    elif progress_callback is not None:
        kwargs["progress_callback"] = progress_callback
    return kwargs


def _review_code_iter(review_domain, progress_callback=None, code_files=None):
    review_code = review_domain.review_code
    kwargs = _get_review_code_kargs(review_code, progress_callback, code_files)
    return review_code(**kwargs)


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
    options = _triage_options_for_runtime(args, runtime)

    output_target = None
    if args.output_file:
        sarif_targets = [
            p for p in args.output_file if str(p).lower().endswith(".sarif")
        ]
        if sarif_targets:
            output_target = sarif_targets[0]

    def _invoke(debug_callback=None, progress_callback=None):
        return engine.triage_sarif_file(
            findings_path,
            output_target,
            options=options,
            debug_callback=debug_callback,
            progress_callback=progress_callback,
        )

    saved_path = run_triage_action(
        args,
        action=_invoke,
        spinner_text="Triaging SARIF findings...",
    )
    print_console(
        f"[green]Triage complete. SARIF saved to {escape(str(saved_path))}[/green]",
        args.quiet,
    )


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

    options = _triage_options_for_runtime(args, runtime)
    sarif_payload = generate_sarif(results)

    def _invoke(debug_callback=None, progress_callback=None):
        return engine.triage_sarif_payload(
            sarif_payload,
            options=options,
            debug_callback=debug_callback,
            progress_callback=progress_callback,
        )

    triaged_sarif = run_triage_action(
        args,
        action=_invoke,
        spinner_text="Triaging JSON findings...",
    )

    output_files = args.output_file or [json_path]
    save_output(output_files, results, args.quiet, sarif_payload=triaged_sarif)
    print_console("[green]Triage complete.[/green]", args.quiet)


def _build_triaged_sarif_payload(engine, results, args, runtime: CommandRuntime):
    if not getattr(args, "triage", False):
        return None
    try:
        sarif_payload = generate_sarif(results)
        options = _triage_options_for_runtime(args, runtime)

        def _invoke(debug_callback=None, progress_callback=None):
            return engine.triage_sarif_payload(
                sarif_payload,
                options=options,
                debug_callback=debug_callback,
                progress_callback=progress_callback,
            )

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


def _finalize_review_output(engine, results, args, runtime: CommandRuntime):
    pretty_print_reviews(results, args.quiet)
    sarif_payload = _build_triaged_sarif_payload(engine, results, args, runtime)
    save_output(args.output_file, results, args.quiet, sarif_payload=sarif_payload)
