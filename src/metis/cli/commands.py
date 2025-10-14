# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import importlib
from rich.console import Console
from rich.markup import escape

from metis.utils import read_file_content, safe_decode_unicode
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


console = Console()


def show_help():
    console.print(
        """
[bold blue]Metis CLI[/bold blue]

Type one of the following commands (with arguments):

- [cyan]index[/cyan]
- [cyan]review_patch mypatch.diff[/cyan]
- [cyan]review_file path_to_file/myfile.c[/cyan]
- [cyan]review_code[/cyan]
- [cyan]update patch.diff[/cyan]
- [cyan]ask "Give me an overview of the code"[/cyan]
- [magenta]exit[/magenta]   (quit the tool)
- [magenta]help[/magenta]   (show this message)

Options:
    --backend chroma|postgres  Vector backend to use (default: chroma).
    --output-file PATH         Save analysis results to this file.
    --project-schema SCHEMA    (Optional) Project identifier if postresql is used.
    --chroma-dir DIR           (Optional) Directory to store ChromaDB data (default: ./chromadb).
    --verbose                  (Optional) Shows detailed output in the terminal window.
    --version                  (Optional) Show program version
"""
    )


def show_version():
    version = importlib.metadata.version("metis")
    console.print("Metis [green]" + version + "[/green]")


def run_review(engine, patch_file, args):
    if not check_file_exists(patch_file):
        return
    results = with_spinner(
        "Reviewing patch...",
        engine.review_patch,
        patch_file=patch_file,
        quiet=args.quiet,
    )
    pretty_print_reviews(results, args.quiet)
    save_output(args.output_file, results, args.quiet)


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

    pretty_print_reviews(results, args.quiet)
    save_output(args.output_file, results, args.quiet)


def run_review_code(engine, args):
    if args.verbose:
        print_console("[cyan]Reviewing codebase...[/cyan]", args.quiet)
        total = len(engine.get_code_files())
        file_reviews = iterate_with_progress(total, engine.review_code(False))
        results = {"reviews": file_reviews}
    else:
        results = with_spinner(
            "Reviewing codebase...", collect_reviews, engine, False, quiet=args.quiet
        )
    pretty_print_reviews(results, args.quiet)
    save_output(args.output_file, results, args.quiet)


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


def run_ask(engine, question):
    answer = with_spinner("Thinking...", engine.ask_question, question)
    print_console("[bold magenta]Metis Answer:[/bold magenta]\n")
    if isinstance(answer, dict):
        if "code" in answer:
            print_console(
                f"[bold yellow]Code Context:[/bold yellow] {escape(safe_decode_unicode(answer['code']))} \n"
            )
        if "docs" in answer:
            print_console(
                f"[bold blue]Documentation Context:[/bold blue] {escape(safe_decode_unicode(answer['docs']))}"
            )
    else:
        print_console(escape(str(answer)))
