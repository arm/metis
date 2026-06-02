# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import importlib
import inspect
from pathlib import Path
from rich.markup import escape

from metis.engine.options import ReviewOptions, TriageOptions
from .command_runtime import CommandRuntime
from metis.utils import read_file_content, safe_decode_unicode
from metis.sarif.writer import generate_sarif
from metis.usage import usage_operation
from .triage_cli import run_triage_action
from .utils import (
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


def _print_no_index_warning(args, runtime: CommandRuntime):
    if runtime.use_retrieval_context:
        return
    if runtime.no_index_warning_emitted:
        return
    print_console(
        "[yellow]Warning:[/yellow] Running without index; relevant-context retrieval was skipped.",
        args.quiet,
    )
    runtime.no_index_warning_emitted = True


def _review_options_for_runtime(runtime: CommandRuntime) -> ReviewOptions:
    return ReviewOptions(use_retrieval_context=runtime.use_retrieval_context)


def _triage_options_for_runtime(args, runtime: CommandRuntime) -> TriageOptions:
    return TriageOptions(
        use_retrieval_context=runtime.use_retrieval_context,
        include_triaged=bool(getattr(args, "include_triaged", False)),
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
    --ignore-index             Allow review_file, review_code, review_patch, and triage to run without index-backed context.
    --project-schema SCHEMA    (Optional) Project identifier if postgresql is used.
    --chroma-dir DIR           (Optional) Directory to store ChromaDB data (default: ./chromadb).
    --verbose                  (Optional) Shows detailed output in the terminal window.
    --version                  (Optional) Show program version
"""
    )


def show_version(args=None):
    version = importlib.metadata.version("metis")
    print_console("Metis [green]" + version + "[/green]")


def run_review(engine, patch_file, args, runtime: CommandRuntime):
    if not check_file_exists(patch_file):
        return
    _print_no_index_warning(args, runtime)
    options = _review_options_for_runtime(runtime)
    results = with_spinner(
        "Reviewing patch...",
        engine.review.review_patch,
        patch_file=patch_file,
        options=options,
        quiet=args.quiet,
    )
    _finalize_review_output(engine, results, args, runtime)


def run_file_review(engine, file_path, args, runtime: CommandRuntime):
    if not check_file_exists(file_path):
        return
    _print_no_index_warning(args, runtime)
    options = _review_options_for_runtime(runtime)
    raw_result = with_spinner(
        f"Reviewing file {file_path}...",
        engine.review.review_file,
        file_path=file_path,
        options=options,
        quiet=args.quiet,
    )

    if raw_result and isinstance(raw_result.get("reviews"), list):
        results = {"reviews": [raw_result]}
    else:
        results = {"reviews": []}

    _finalize_review_output(engine, results, args, runtime)


def run_review_code(engine, args, runtime: CommandRuntime):
    _print_no_index_warning(args, runtime)
    options = _review_options_for_runtime(runtime)
    if not args.quiet:
        print_console("[cyan]Reviewing codebase...[/cyan]", args.quiet)
        total = len(engine.review.get_code_files(options=options))
        file_reviews = _collect_review_code_with_progress(
            engine,
            options,
            total,
        )
        results = {"reviews": file_reviews}
    elif args.verbose:
        total = len(engine.review.get_code_files(options=options))
        file_reviews = iterate_with_progress(
            total,
            _review_code_iter(engine.review, options),
        )
        results = {"reviews": file_reviews}
    else:
        results = with_spinner(
            "Reviewing codebase...",
            collect_reviews,
            engine,
            options=options,
            quiet=args.quiet,
        )
    _finalize_review_output(engine, results, args, runtime)


def _collect_review_code_with_progress(engine, options, total):
    results = []
    with build_standard_progress(transient=True) as progress:
        task = progress.add_task("[cyan]Reviewing codebase...[/cyan]", total=total or 1)
        callback = _make_review_code_progress_callback(progress, task, total)
        for item in _review_code_iter(
            engine.review,
            options,
            progress_callback=callback,
        ):
            if item is not None:
                results.append(item)
            callback.review_result()
        callback.finish()
    return results


def _review_code_iter(review_domain, options, progress_callback=None):
    review_code = review_domain.review_code
    if progress_callback is None:
        return review_code(options=options)
    try:
        signature = inspect.signature(review_code)
    except (TypeError, ValueError):
        signature = None
    if signature is not None:
        params = signature.parameters
        accepts_kwargs = any(
            param.kind == inspect.Parameter.VAR_KEYWORD for param in params.values()
        )
        if "progress_callback" in params or accepts_kwargs:
            return review_code(options=options, progress_callback=progress_callback)
    return review_code(options=options)


def _make_review_code_progress_callback(progress, task, review_total):
    class _ReviewProgress:
        def __init__(self):
            self.review_completed = 0

        def __call__(self, event):
            kind = str((event or {}).get("event") or "")
            if kind == "treesitter_graph_start":
                total = _positive_int(event.get("total"))
                progress.update(
                    task,
                    total=total,
                    completed=0,
                    description="[cyan]Building reachability graph...[/cyan]",
                )
                return
            if kind == "treesitter_graph_progress":
                total = _positive_int(event.get("total"))
                completed = _positive_int(event.get("completed")) or 0
                file_name = escape(str(event.get("file") or ""))
                progress.update(
                    task,
                    total=total,
                    completed=completed,
                    description=f"[cyan]Building reachability graph: {file_name}[/cyan]",
                )
                return
            if kind == "treesitter_graph_done":
                progress.update(
                    task,
                    total=None,
                    description=(
                        "[cyan]Reachability graph ready: "
                        f"{event.get('nodes', 0)} functions, "
                        f"{event.get('edges', 0)} calls[/cyan]"
                    ),
                )
                return
            if kind == "treesitter_paths_done":
                progress.update(
                    task,
                    total=None,
                    description=(
                        "[cyan]Reachability paths ready: "
                        f"{event.get('paths', 0)} paths, "
                        f"{event.get('selected', 0)} selected[/cyan]"
                    ),
                )
                return
            if kind == "intra_audit_start":
                total = _positive_int(event.get("files"))
                progress.update(
                    task,
                    total=total,
                    completed=0,
                    description="[cyan]Running intra-file reachability audit...[/cyan]",
                )
                return
            if kind == "intra_audit_progress":
                total = _positive_int(event.get("total"))
                completed = _positive_int(event.get("completed")) or 0
                file_name = escape(str(event.get("file") or ""))
                progress.update(
                    task,
                    total=total,
                    completed=completed,
                    description=f"[cyan]Auditing reachability: {file_name}[/cyan]",
                )
                return
            if kind == "confirmation_start":
                total = _positive_int(event.get("total"))
                progress.update(
                    task,
                    total=total,
                    completed=0,
                    description="[cyan]Confirming reachable paths...[/cyan]",
                )
                return
            if kind == "confirmation_progress":
                total = _positive_int(event.get("total"))
                completed = _positive_int(event.get("completed")) or 0
                progress.update(
                    task,
                    total=total,
                    completed=completed,
                    description="[cyan]Confirming reachable paths...[/cyan]",
                )
                return
            if kind == "confirmation_done":
                progress.update(
                    task,
                    total=None,
                    description=(
                        "[cyan]Path confirmation done: "
                        f"{event.get('confirmed', 0)} findings[/cyan]"
                    ),
                )
                return
            if kind == "supplementary_done":
                progress.update(
                    task,
                    total=None,
                    description=(
                        "[cyan]Reachability lenses done: "
                        f"{event.get('total', 0)} findings[/cyan]"
                    ),
                )
                return
            if kind == "treesitter_code_review_done":
                progress.update(
                    task,
                    total=None,
                    description=(
                        "[cyan]Reachability review done: "
                        f"{event.get('deduped_findings', 0)} findings across "
                        f"{event.get('files', 0)} files[/cyan]"
                    ),
                )
                return
            if kind.endswith("_start"):
                progress.update(
                    task,
                    total=None,
                    description=f"[cyan]Running {_progress_event_label(kind)}...[/cyan]",
                )
                return
            if kind.endswith("_done"):
                progress.update(
                    task,
                    total=None,
                    description=f"[cyan]Finished {_progress_event_label(kind)}[/cyan]",
                )
                return

        def review_result(self):
            self.review_completed += 1
            total = review_total or self.review_completed
            progress.update(
                task,
                total=total,
                completed=min(self.review_completed, total),
                description=(
                    "[cyan]Collecting review results "
                    f"{self.review_completed}/{total}[/cyan]"
                ),
            )

        def finish(self):
            progress.update(
                task,
                total=1,
                completed=1,
                description="[green]Review complete[/green]",
            )

    return _ReviewProgress()


def _positive_int(value):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _progress_event_label(event_name):
    text = str(event_name or "")
    for suffix in ("_start", "_done"):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
    return escape(text.replace("_", " "))


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


def run_triage(engine, sarif_path, args, runtime: CommandRuntime):
    if not check_file_exists(sarif_path, quiet=args.quiet):
        return
    if Path(sarif_path).suffix.lower() != ".sarif":
        print_console("[red]Only .sarif input files are supported.[/red]", args.quiet)
        return
    _print_no_index_warning(args, runtime)
    print_console("[cyan]Loading SARIF findings...[/cyan]", args.quiet)
    options = _triage_options_for_runtime(args, runtime)

    output_target = None
    if args.output_file:
        sarif_targets = [
            p for p in args.output_file if str(p).lower().endswith(".sarif")
        ]
        if sarif_targets:
            output_target = sarif_targets[0]

    def _invoke(kwargs):
        return engine.triage_sarif_file(
            sarif_path,
            output_target,
            options=options,
            **kwargs,
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


def _build_triaged_sarif_payload(engine, results, args, runtime: CommandRuntime):
    if not getattr(args, "triage", False):
        return None
    try:
        sarif_payload = generate_sarif(results)
        _print_no_index_warning(args, runtime)
        options = _triage_options_for_runtime(args, runtime)

        def _invoke(kwargs):
            return engine.triage_sarif_payload(
                sarif_payload,
                options=options,
                **kwargs,
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
