# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0


import importlib
import json
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


def _reachability_setting(engine, args, arg_name: str, setting_name: str, default=None):
    value = getattr(args, arg_name, None)
    if value is not None:
        return value
    settings = getattr(engine, "reachability_settings", {}) or {}
    value = settings.get(setting_name)
    return default if value is None else value


def _parse_review_file_options(runtime: CommandRuntime):
    mode = "partial"
    context_budget = None
    extra = list(runtime.command_args[1:])
    i = 0
    while i < len(extra):
        arg = extra[i]
        if arg == "--full":
            mode = "full"
            i += 1
            continue
        if arg == "--partial":
            mode = "partial"
            i += 1
            continue
        if arg == "--mode" and i + 1 < len(extra):
            mode = str(extra[i + 1]).lower()
            i += 2
            continue
        if arg == "--context-budget" and i + 1 < len(extra):
            try:
                context_budget = int(extra[i + 1])
            except ValueError:
                context_budget = None
            i += 2
            continue
        i += 1
    if mode not in {"partial", "full"}:
        mode = "partial"
    return mode, context_budget


def show_help(args=None):
    print_console(
        """
[bold blue]Metis CLI[/bold blue]

Type one of the following commands (with arguments):

- [cyan]index[/cyan]
- [cyan]review_patch mypatch.diff[/cyan]
- [cyan]review_file path_to_file/myfile.c[/cyan]
  - default uses tree-sitter reachability scoped to the reviewed file; add [cyan]--mode full[/cyan] for codebase reachability.
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
    --reachability-confirmation-model MODEL  Model for vulnerability analysis (default: gpt-5.5).
    --reachability-reasoning-effort LEVEL    Reasoning effort when supported: none|minimal|low|medium|high (default: high).
    --reachability-max-paths-per-sink N      Max diverse paths per root-cause sink (default: 3)
    --reachability-workers N                 Parallel workers (default: 8)
    --reachability-max-path N                Max paths to analyze, 0=all (default: 0)
    review_file options: --mode partial|full, --full, --context-budget N
    review_file, review_code, and reachability use tree-sitter for graph construction and AI confirmation.
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


def _run_file_review_with(
    engine,
    file_path,
    args,
    runtime: CommandRuntime,
    review_file_func,
):
    original_file_path = file_path
    if not Path(str(file_path)).is_file():
        codebase_path = getattr(engine, "codebase_path", None)
        if codebase_path:
            candidate = Path(str(codebase_path)) / str(file_path)
            if candidate.is_file():
                file_path = str(candidate)
    if not check_file_exists(file_path):
        if original_file_path != file_path:
            check_file_exists(original_file_path)
        missing_result = {
            "reviews": [
                {
                    "file": str(original_file_path),
                    "file_path": str(original_file_path),
                    "reviews": [],
                    "errors": [f"File not found: {original_file_path}"],
                }
            ]
        }
        _finalize_review_output(engine, missing_result, args, runtime)
        return
    _print_no_index_warning(args, runtime)
    options = _review_options_for_runtime(runtime)
    mode, context_budget = _parse_review_file_options(runtime)

    def _progress(event):
        if not args.verbose:
            return
        ev = event.get("event", "")
        if ev == "treesitter_graph_start":
            print_console(
                f"[cyan]Building tree-sitter reachability graph for {event.get('total', 0)} C/C++ files...[/cyan]",
                args.quiet,
            )
        elif ev == "treesitter_graph_done":
            print_console(
                f"[green]Tree-sitter graph: {event.get('nodes', 0)} functions, "
                f"{event.get('edges', 0)} edges, {event.get('sources', 0)} sources, "
                f"{event.get('sinks', 0)} sinks[/green]",
                args.quiet,
            )
        elif ev == "treesitter_file_paths_done":
            print_console(
                f"[green]Tree-sitter source-to-file paths for {escape(str(event.get('file', '')))}: "
                f"{event.get('source_to_file_paths', event.get('paths', 0))}"
                f" | outgoing context={event.get('outgoing_context_paths', 0)}"
                f" | focus nodes={event.get('focus_nodes', 0)}[/green]",
                args.quiet,
            )
        elif ev == "treesitter_file_review_done":
            print_console(
                f"[green]Tree-sitter file review: supplementary={event.get('supplementary_findings', 0)}, "
                f"paths={event.get('path_findings', 0)}, deterministic={event.get('deterministic_findings', 0)}[/green]",
                args.quiet,
            )
        elif ev == "treesitter_file_review_error":
            print_console(
                f"[red]Tree-sitter file review error in {escape(str(event.get('file', 'unknown')))}: "
                f"{escape(str(event.get('error', 'unknown error')))}[/red]",
                args.quiet,
            )
        elif ev.endswith("_start"):
            count = event.get("functions") or event.get("files") or event.get("globals") or 0
            print_console(
                f"[cyan]{escape(str(ev).replace('_', ' '))}: {count} candidate(s)[/cyan]",
                args.quiet,
            )
        elif ev.endswith("_done") and ev != "treesitter_file_review_done":
            if "findings" in event:
                print_console(
                    f"[green]{escape(str(ev).replace('_', ' '))}: "
                    f"{event.get('findings', 0)} finding(s)[/green]",
                    args.quiet,
                )
        elif ev == "partial_symbol_index_start":
            print_console(f"[cyan]Building symbol index for {event.get('files', 0)} C/C++ files...[/cyan]", args.quiet)
        elif ev == "partial_symbol_index_done":
            print_console(
                f"[green]Symbol index: {event.get('definitions', 0)} functions, "
                f"{event.get('callsites', 0)} callsites[/green]",
                args.quiet,
            )
        elif ev == "partial_target_extract_start":
            print_console(f"[cyan]Extracting target anchors from {escape(str(event.get('file', '')))}...[/cyan]", args.quiet)
        elif ev == "partial_context_done":
            print_console(
                f"[green]Partial context: target={event.get('target_nodes', 0)}, "
                f"inbound={event.get('inbound', 0)}, outbound={event.get('outbound', 0)}, "
                f"shared={event.get('shared', 0)}, lifecycle={event.get('lifecycle', 0)}, "
                f"callbacks={event.get('callbacks', 0)}[/green]",
                args.quiet,
            )
        elif ev == "partial_graph_done":
            print_console(
                f"[green]Partial graph: {event.get('nodes', 0)} nodes, "
                f"{event.get('edges', 0)} edges, {event.get('paths', 0)} paths[/green]",
                args.quiet,
            )
        elif ev == "partial_review_done" and "deduped_findings" in event:
            print_console(
                f"[green]Partial review: {event.get('deduped_findings', 0)} findings "
                f"after filtering[/green]",
                args.quiet,
            )
        elif ev == "partial_review_error":
            print_console(
                f"[red]Partial review LLM error in {escape(str(event.get('pass', 'unknown')))}: "
                f"{escape(str(event.get('error', 'unknown error')))}[/red]",
                args.quiet,
            )

    mode_label = f"{mode} mode"
    try:
        raw_result = with_spinner(
            f"Reviewing file {file_path} ({mode_label})...",
            review_file_func,
            file_path=file_path,
            options=options,
            mode=mode,
            context_budget=context_budget,
            progress_callback=_progress,
            quiet=args.quiet,
        )

        if raw_result and isinstance(raw_result.get("reviews"), list):
            results = {"reviews": [raw_result]}
        else:
            results = {"reviews": []}

        _finalize_review_output(engine, results, args, runtime)
    except Exception as exc:
        error_result = {
            "reviews": [
                {
                    "file": str(original_file_path),
                    "file_path": str(file_path),
                    "reviews": [],
                    "errors": [f"{type(exc).__name__}: {exc}"],
                }
            ]
        }
        save_output(args.output_file, error_result, args.quiet)


def run_file_review(engine, file_path, args, runtime: CommandRuntime):
    return _run_file_review_with(
        engine,
        file_path,
        args,
        runtime,
        engine.review.review_file,
    )


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


def _write_paths_jsonl(paths, graph, output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        for idx, path in enumerate(paths, start=1):
            source = graph.get_node(path.source)
            sink = graph.get_node(path.sink)
            row = {
                "index": idx,
                "source": path.source,
                "source_file": source.file_path if source else "",
                "source_line": source.line_number if source else 0,
                "sink": path.sink,
                "sink_file": sink.file_path if sink else "",
                "sink_line": sink.line_number if sink else 0,
                "sink_type": path.sink_type,
                "path": list(path.path),
                "length": len(path.path),
            }
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


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
    from metis.engine.reachability_service_modular.service import (
        DEFAULT_TREESITTER_OUTPUT_DIR,
    )

    confirmation_model = _reachability_setting(
        engine, args, "reachability_confirmation_model", "confirmation_model", "gpt-5.5"
    )
    reasoning_effort = _reachability_setting(
        engine, args, "reachability_reasoning_effort", "reasoning_effort"
    )
    max_paths_per_sink = _reachability_setting(
        engine, args, "reachability_max_paths_per_sink", "max_paths_per_sink", 3
    )
    workers = _reachability_setting(engine, args, "reachability_workers", "max_workers", 8)
    max_paths_limit = _reachability_setting(engine, args, "reachability_max_paths", "max_paths", 0)
    q = args.quiet

    output_dir = engine.reachability.default_output_dir()
    findings_path = None
    if args.output_file:
        jsonl = [p for p in args.output_file if str(p).lower().endswith(".jsonl")]
        if jsonl:
            findings_path = Path(str(jsonl[0]))
            output_dir = findings_path.parent
        else:
            output_dir = Path(str(args.output_file[0]))
    if not findings_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        findings_path = output_dir / f"findings_{timestamp}.jsonl"
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    graph_path = output_dir / f"graph_{timestamp}.jsonl"
    paths_path = output_dir / f"paths_{timestamp}.jsonl"
    raw_findings_path = output_dir / f"findings_raw_{timestamp}.jsonl"
    supplementary_findings_path = output_dir / f"findings_supplementary_raw_{timestamp}.jsonl"

    files = engine.reachability.get_c_cpp_files()
    if not files:
        print_console("[yellow]No C/C++ files found in codebase.[/yellow]", q)
        return

    print_console(
        f"\n[bold cyan]Metis Reachability[/bold cyan]\n"
        f"  Files: {len(files)}\n"
        f"  Analysis model: {escape(str(confirmation_model))}"
        f"{' | reasoning=' + escape(str(reasoning_effort)) if reasoning_effort else ''}\n"
        f"  Output: {escape(str(output_dir or DEFAULT_TREESITTER_OUTPUT_DIR))}",
        q,
    )

    def _graph_cb(event):
        ev = event.get("event", "")
        if ev == "treesitter_graph_start":
            print_console(f"\n[cyan]Phase 1/5 - Building deterministic graph from {event['total']} files[/cyan]", q)
        elif ev == "treesitter_graph_progress" and args.verbose:
            print_console(
                f"  [{event['completed']}/{event['total']}] "
                f"{escape(str(event.get('file', '')))} "
                f"functions={event.get('functions', 0)} globals={event.get('globals', 0)}",
                q,
            )
            for error in event.get("error_messages", []) or []:
                print_console(f"    [yellow]{escape(str(error))}[/yellow]", q)
        elif ev == "treesitter_graph_done":
            print_console(
                f"[green]  Graph: {event['nodes']} functions, {event['edges']} edges, "
                f"{event['sources']} sources, {event['sinks']} sinks[/green]",
                q,
            )
            if event.get("errors"):
                errors = event.get("errors") or []
                print_console(f"[yellow]  Parse issues: {len(errors)}[/yellow]", q)
                for error in errors[:8]:
                    print_console(f"    [yellow]{escape(str(error))}[/yellow]", q)
                if len(errors) > 8:
                    print_console(f"    [yellow]... {len(errors) - 8} more[/yellow]", q)

    with usage_operation("reachability"):
        graph = engine.reachability.build_graph(
            files,
            progress_callback=_graph_cb,
        )

    if graph.node_count() == 0:
        print_console("[yellow]Tree-sitter graph empty - no functions extracted.[/yellow]", q)
        return

    graph.save_jsonl(graph_path, include_globals=True)
    print_console(f"  Graph saved: {escape(str(graph_path))}", q)

    print_console("\n[cyan]Phase 2/5 - Tracing source-to-sink paths[/cyan]", q)
    paths = engine.reachability.trace_paths(graph)
    if max_paths_limit > 0:
        paths_to_analyze = paths[:max_paths_limit]
    else:
        paths_to_analyze = paths
    _write_paths_jsonl(paths, graph, paths_path)
    print_console(
        f"  Paths: [bold]{len(paths)}[/bold] | Selected: [bold]{len(paths_to_analyze)}[/bold]\n"
        f"  Paths saved: {escape(str(paths_path))}",
        q,
    )

    def _supp_cb(event):
        ev = str(event.get("event", ""))
        if ev.endswith("_start"):
            count = event.get("functions") or event.get("files") or event.get("globals") or 0
            print_console(
                f"  [cyan]{escape(ev.replace('_', ' '))}: {count} candidate(s)[/cyan]",
                q,
            )
        elif ev.endswith("_done") and ev != "supplementary_done":
            print_console(
                f"  [green]{escape(ev.replace('_', ' '))}: "
                f"{event.get('findings', 0)} finding(s)[/green]",
                q,
            )
        elif ev == "supplementary_done":
            print_console(
                f"[green]  Supplementary findings: {event.get('total', 0)}[/green]",
                q,
            )

    print_console("\n[cyan]Phase 3/5 - Supplementary semantic audit[/cyan]", q)
    with usage_operation("reachability"):
        supplementary_findings = engine.reachability.run_supplementary_analysis(
            graph,
            audit_model=confirmation_model,
            strong_model=confirmation_model,
            max_workers=workers,
            progress_callback=_supp_cb,
            reasoning_effort=reasoning_effort,
        )
    from metis.engine.reachability_common import _write_jsonl

    _write_jsonl(str(supplementary_findings_path), supplementary_findings)

    if not paths_to_analyze:
        print_console("[yellow]No source-to-sink paths selected for AI path review.[/yellow]", q)
        findings = []
    else:
        findings = None

    def _confirm_cb(event):
        ev = event.get("event", "")
        if ev == "confirmation_start":
            print_console(f"\n[cyan]Phase 4/5 - Confirming paths across {event['total']} sinks[/cyan]", q)
        elif ev == "confirmation_progress" and args.verbose:
            print_console(
                f"  [{event['completed']}/{event['total']}] {escape(str(event.get('sink', '')))}",
                q,
            )
        elif ev == "confirmation_error":
            print_console(
                f"  [red]LLM error for {escape(str(event.get('sink', '')))}: "
                f"{escape(str(event.get('error', 'unknown error')))}[/red]",
                q,
            )
        elif ev == "confirmation_done":
            print_console(f"[green]  Confirmed findings: {event['confirmed']}[/green]", q)

    if findings is None:
        with usage_operation("reachability"):
            findings = engine.reachability.confirm_paths(
                paths_to_analyze,
                graph,
                confirmation_model=confirmation_model,
                max_workers=workers,
                output_path=str(raw_findings_path),
                progress_callback=_confirm_cb,
                reasoning_effort=reasoning_effort,
            )

    all_findings = list(supplementary_findings) + list(findings)
    print_console("\n[cyan]Phase 5/5 - Deduplicating findings[/cyan]", q)
    if not all_findings:
        print_console(
            f"[yellow]No vulnerabilities confirmed.[/yellow]\n"
            f"  Raw findings: {escape(str(raw_findings_path))}\n"
            f"  Supplementary raw findings: {escape(str(supplementary_findings_path))}\n"
            f"  Graph: {escape(str(graph_path))}",
            q,
        )
        return

    with usage_operation("reachability"):
        deduped, total_before, removed = engine.reachability.deduplicate_and_write(
            all_findings,
            str(findings_path),
            max_paths_per_sink=max_paths_per_sink,
        )

    print_console(
        f"[green]  Findings: {total_before} raw, {len(deduped)} after dedupe "
        f"({removed} removed)[/green]\n"
        f"  Findings:     {escape(str(findings_path))}\n"
        f"  Raw findings: {escape(str(raw_findings_path))}\n"
        f"  Supplementary raw findings: {escape(str(supplementary_findings_path))}\n"
        f"  Graph:        {escape(str(graph_path))}\n"
        f"  Paths:        {escape(str(paths_path))}",
        q,
    )
