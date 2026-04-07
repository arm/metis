# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import importlib
from pathlib import Path
from rich.markup import escape

from metis.utils import read_file_content, safe_decode_unicode
from metis.sarif.writer import generate_sarif
from .triage_cli import run_triage_action
from .utils import (
    check_file_exists,
    with_spinner,
    with_timer,
    collect_reviews,
    iterate_with_progress,
    count_index_items,
    pretty_print_reviews,
    save_output,
    print_console,
)


def show_help(args=None):
    print_console(
        """
[bold blue]Metis CLI[/bold blue]

Type one of the following commands (with arguments):

- [cyan]index[/cyan]
- [cyan]review_patch mypatch.diff[/cyan]
- [cyan]review_file path_to_file/myfile.c[/cyan]
- [cyan]review_code[/cyan]
- [cyan]triage findings.sarif[/cyan]
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
    --project-schema SCHEMA    (Optional) Project identifier if postgresql is used.
    --chroma-dir DIR           (Optional) Directory to store ChromaDB data (default: ./chromadb).
    --verbose                  (Optional) Shows detailed output in the terminal window.
    --version                  (Optional) Show program version
""",
        getattr(args, "quiet", False),
    )


def show_version(args=None):
    version = importlib.metadata.version("metis")
    print_console("Metis [green]" + version + "[/green]", getattr(args, "quiet", False))


def run_review(engine, patch_file, args):
    if not check_file_exists(patch_file):
        return
    results = with_spinner(
        "Reviewing patch...",
        engine.review_patch,
        patch_file=patch_file,
        quiet=args.quiet,
    )
    _finalize_review_output(engine, results, args)


def run_file_review(engine, file_path, args):
    if not check_file_exists(file_path):
        return
    raw_result = with_spinner(
        f"Reviewing file {file_path}...",
        engine.review_file,
        file_path=file_path,
        quiet=args.quiet,
    )

    if raw_result and isinstance(raw_result.get("reviews"), list):
        results = {"reviews": [raw_result]}
    else:
        results = {"reviews": []}

    _finalize_review_output(engine, results, args)


def run_review_code(engine, args):
    if args.verbose:
        print_console("[cyan]Reviewing codebase...[/cyan]", args.quiet)
        total = len(engine.get_code_files())
        file_reviews = iterate_with_progress(total, engine.review_code())
        results = {"reviews": file_reviews}
    else:
        results = with_spinner(
            "Reviewing codebase...", collect_reviews, engine, quiet=args.quiet
        )
    _finalize_review_output(engine, results, args)


def run_index(engine, verbose=False, quiet=False):
    if verbose:
        print_console("[cyan]Indexing codebase...[/cyan]", quiet)
        total = count_index_items(engine)
        if total > 0:
            iterate_with_progress(total, engine.index_prepare_nodes_iter())
            with_timer(
                "Embedding indexes...", engine.index_finalize_embeddings, quiet=quiet
            )
            print_console("[green]Indexing completed successfully.[/green]", quiet)
            return

    with_spinner("Indexing codebase...", engine.index_codebase, quiet=quiet)
    print_console("[green]Indexing completed successfully.[/green]", quiet)


def run_update(engine, patch_file, args):
    if not check_file_exists(patch_file):
        return
    file_diff = read_file_content(patch_file)
    with_spinner("Updating index...", engine.update_index, file_diff, quiet=args.quiet)
    print_console("[green]Index update completed.[/green]", args.quiet)


def run_ask(engine, question, args):
    answer = with_spinner(
        "Thinking...", engine.ask_question, question, quiet=args.quiet
    )
    print_console("[bold magenta]Metis Answer:[/bold magenta]\n", args.quiet)
    if isinstance(answer, dict):
        if "code" in answer:
            print_console(
                f"[bold yellow]Code Context:[/bold yellow] {escape(safe_decode_unicode(answer['code']))} \n",
                args.quiet,
            )
        if "docs" in answer:
            print_console(
                f"[bold blue]Documentation Context:[/bold blue] {escape(safe_decode_unicode(answer['docs']))}",
                args.quiet,
            )
    else:
        print_console(escape(str(answer)), args.quiet)
    save_output(args.output_file, answer, args.quiet)


def run_triage(engine, sarif_path, args):
    if not check_file_exists(sarif_path, quiet=args.quiet):
        return
    if Path(sarif_path).suffix.lower() != ".sarif":
        print_console("[red]Only .sarif input files are supported.[/red]", args.quiet)
        return
    print_console("[cyan]Loading SARIF findings...[/cyan]", args.quiet)

    output_target = None
    if args.output_file:
        sarif_targets = [
            p for p in args.output_file if str(p).lower().endswith(".sarif")
        ]
        if sarif_targets:
            output_target = sarif_targets[0]

    def _invoke(kwargs):
        return engine.triage_sarif_file(sarif_path, output_target, **kwargs)

    saved_path = run_triage_action(
        args,
        action=_invoke,
        spinner_text="Triaging SARIF findings...",
    )
    print_console(
        f"[green]Triage complete. SARIF saved to {escape(str(saved_path))}[/green]",
        args.quiet,
    )


def _build_triaged_sarif_payload(engine, results, args):
    if not getattr(args, "triage", False):
        return None
    try:
        sarif_payload = generate_sarif(results)

        def _invoke(kwargs):
            return engine.triage_sarif_payload(sarif_payload, **kwargs)

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


def _finalize_review_output(engine, results, args):
    pretty_print_reviews(results, args.quiet)
    sarif_payload = _build_triaged_sarif_payload(engine, results, args)
    save_output(args.output_file, results, args.quiet, sarif_payload=sarif_payload)
