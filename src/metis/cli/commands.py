# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import importlib
from datetime import datetime
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
- [cyan]reachability[/cyan]
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
    --reachability-extraction-model MODEL    Model for function extraction (default: gpt-4.1-mini).
    --reachability-confirmation-model MODEL  Model for deep analysis.
    --reachability-max-paths-per-sink N      Max diverse paths per root-cause sink (default: 3)
    --reachability-workers N                 Parallel workers (default: 8)
    --reachability-max-path N                Max paths to analyze, 0=all (default: 0)
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
    if args.verbose:
        print_console("[cyan]Reviewing codebase...[/cyan]", args.quiet)
        total = len(engine.review.get_code_files(options=options))
        file_reviews = iterate_with_progress(
            total,
            engine.review.review_code(options=options),
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


def run_reachability(engine, args, runtime: CommandRuntime):
    from metis.engine.reachability_service import DEFAULT_OUTPUT_DIR

    extraction_model = getattr(args, "reachability_extraction_model", "gpt-4.1-mini")
    confirmation_model = getattr(args, "reachability_confirmation_model", None)
    max_paths_per_sink = getattr(args, "reachability_max_paths_per_sink", 3)
    workers = getattr(args, "reachability_workers", 8)
    max_paths_limit = getattr(args, "reachability_max_paths", 0)
    is_interactive = not bool(getattr(args, "non_interactive", False))

    output_dir = DEFAULT_OUTPUT_DIR
    findings_path = None
    if args.output_file:
        jsonl = [p for p in args.output_file if str(p).lower().endswith(".jsonl")]
        if jsonl:
            findings_path = str(jsonl[0]); output_dir = str(Path(findings_path).parent)
        else:
            findings_path = str(args.output_file[0]); output_dir = str(Path(findings_path).parent)
    if not findings_path:
        Path(output_dir).mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        findings_path = f"{output_dir}/findings_{ts}.jsonl"

    graph_path = str(Path(output_dir) / "graph.jsonl")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    files = engine.reachability.get_c_cpp_files()
    if not files:
        print_console("[yellow]No C/C++ files found in codebase.[/yellow]", args.quiet)
        return

    confirm_model = confirmation_model or engine.reachability._config.llama_query_model
    q = args.quiet

    print_console(
        f"\n[bold cyan]═══ Metis Reachability Analysis ═══[/bold cyan]\n"
        f"  Files: {len(files)}  |  Extraction: {escape(extraction_model)}  |  "
        f"Strong model: {escape(confirm_model)}  |  Workers: {workers}", q)

    def _ext_cb(e):
        ev = e.get("event", "")
        if ev == "extraction_start":
            print_console(f"\n[cyan]Phase 1/6 — Extracting functions from {e['total']} files...[/cyan]", q)
        elif ev == "extraction_progress" and args.verbose:
            print_console(f"  [{e['completed']}/{e['total']}] {escape(str(e.get('file', '')))}", q)
        elif ev == "extraction_done":
            print_console(f"[green]  ✓ Graph: {e['nodes']} functions, {e['edges']} edges, {e['sources']} sources, {e['sinks']} sinks[/green]", q)
            errs = e.get("errors", [])
            if errs:
                print_console(f"[yellow]  {len(errs)} extraction error(s)[/yellow]", q)

    with usage_operation("reachability"):
        graph = engine.reachability.build_graph(files, extraction_model=extraction_model, max_workers=workers, progress_callback=_ext_cb)

    if graph.node_count() == 0:
        print_console("[yellow]Graph empty — no functions extracted.[/yellow]", q); return

    graph.save_jsonl(graph_path)
    print_console(f"  Graph saved: {escape(graph_path)}", q)

    paths = engine.reachability.trace_paths(graph)
    sinks = {}
    for p in paths: sinks[p.sink] = sinks.get(p.sink, 0) + 1
    print_console(f"\n[cyan]Phase 2/6 — Path tracing[/cyan]\n  Paths: [bold]{len(paths)}[/bold]  |  Unique sinks: [bold]{len(sinks)}[/bold]", q)

    paths_to_analyze = paths
    if max_paths_limit > 0:
        paths_to_analyze = paths[:max_paths_limit]
    elif is_interactive and paths:
        print_console(f"\n  Analyze all {len(paths)} paths or limit?", q)
        try:
            ans = input("  Enter number or 'all' [all]: ").strip()
            if ans and ans.lower() != "all":
                try:
                    n = int(ans)
                    if 0 < n < len(paths): paths_to_analyze = paths[:n]
                except ValueError: pass
        except (EOFError, KeyboardInterrupt): pass


    supp_counts = {}

    def _supp_cb(e):
        ev = e.get("event", "")
        if ev == "intra_audit_start":
            print_console(f"\n[cyan]Phase 3/6 — Intra-function audit ({e['functions']} functions, {e['files']} files)...[/cyan]", q)
        elif ev == "intra_audit_progress" and args.verbose:
            print_console(f"  [{e['completed']}/{e['total']}] {escape(str(e.get('file', '')))}", q)
        elif ev == "lifecycle_audit_start":
            print_console(f"\n[cyan]Phase 4/6 — Lifecycle audit ({e['functions']} functions)...[/cyan]", q)
        elif ev == "lifecycle_audit_done":
            print_console(f"[green]  ✓ Lifecycle: {e['findings']} findings[/green]", q)
        elif ev == "ownership_audit_start":
            print_console(f"\n[cyan]Phase 5a/6 — Resource ownership audit ({e['functions']} functions)...[/cyan]", q)
        elif ev == "ownership_audit_done":
            print_console(f"[green]  ✓ Ownership: {e['findings']} findings[/green]", q)
        elif ev == "semantic_audit_start":
            print_console(f"[cyan]Phase 5b/6 — Semantic correctness audit ({e['functions']} functions)...[/cyan]", q)
        elif ev == "semantic_audit_done":
            print_console(f"[green]  ✓ Semantic: {e['findings']} findings[/green]", q)
        elif ev == "supplementary_done":
            supp_counts.update(e)
            print_console(f"\n[green]  Supplementary total: {e.get('total', 0)} findings[/green]", q)

    with usage_operation("reachability"):
        supp_findings = engine.reachability.run_supplementary_analysis(
            graph, audit_model=extraction_model, strong_model=confirmation_model,
            max_workers=workers, progress_callback=_supp_cb)

    reach_findings = []
    if paths_to_analyze:
        def _conf_cb(e):
            ev = e.get("event", "")
            if ev == "confirmation_start":
                print_console(f"\n[cyan]Phase 6/6 — Confirming {len(paths_to_analyze)} paths across {e['total']} sinks...[/cyan]", q)
            elif ev == "confirmation_progress" and args.verbose:
                print_console(f"  [{e['completed']}/{e['total']}] {escape(str(e.get('sink', '')))}", q)
            elif ev == "confirmation_done":
                print_console(f"[green]  ✓ Reachability: {e['confirmed']} confirmed[/green]", q)

        with usage_operation("reachability"):
            reach_findings = engine.reachability.confirm_paths(
                paths_to_analyze, graph, confirmation_model=confirmation_model,
                max_workers=workers, progress_callback=_conf_cb)

    all_findings = reach_findings + supp_findings
    if not all_findings:
        print_console("\n[yellow]No vulnerabilities confirmed.[/yellow]", q); return

    with usage_operation("reachability"):
        deduped, total_before, removed = engine.reachability.deduplicate_and_write(
            all_findings, findings_path, max_paths_per_sink=max_paths_per_sink)

    by_type = {}
    for f in deduped: by_type[f.analysis_type] = by_type.get(f.analysis_type, 0) + 1

    print_console(
        f"\n[bold green]═══  Analysis Complete  ═══[/bold green]\n"
        f"  Total confirmed:  {total_before}\n"
        f"  After dedup:      {len(deduped)} ({removed} duplicates removed)", q)
    for at, cnt in sorted(by_type.items()):
        print_console(f"    {at}: {cnt}", q)
    print_console(
        f"  Findings: {escape(findings_path)}\n"
        f"  Graph:    {escape(graph_path)}", q)
