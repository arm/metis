# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import contextlib
import hashlib
import importlib.metadata
import logging
import os
import re
import warnings
from datetime import datetime
from pathlib import Path
import sys
from importlib.resources import files

from rich.console import Console
from rich.errors import MarkupError
from metis.runlog import RunLogConfig
from metis.runlog import build_run_metadata
from metis.runlog import open_runlog
from metis import runlog
from metis.json_io import write_json_atomic
from rich.markup import escape
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from .exporters import export_csv, export_html, export_sarif
from metis.sarif.triage import apply_triage_annotations
from metis.vector_store.retrievers import retriever_query_config

try:
    METIS_VERSION = importlib.metadata.version("metis")
except importlib.metadata.PackageNotFoundError:
    METIS_VERSION = "unknown"


console = Console()
logger = logging.getLogger("metis")
REPORT_TEMPLATE = (
    files("metis.cli").joinpath("report_template.html").read_text(encoding="utf-8")
)

try:
    from metis.vector_store.pgvector_store import PGVectorStoreImpl

    PG_SUPPORTED = True
except ImportError:
    PG_SUPPORTED = False


def configure_logger(logger, args):
    if logger.hasHandlers():
        logger.handlers.clear()

    default_level = logging.ERROR
    requested_level = getattr(args, "log_level", None)
    if isinstance(requested_level, str):
        level = logging._nameToLevel.get(requested_level.upper(), default_level)
    else:
        level = default_level

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if getattr(args, "log_file", None):
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.setLevel(level)
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    logging.captureWarnings(True)
    warnings.resetwarnings()
    if level <= logging.WARNING:
        warnings.filterwarnings("default")
    else:
        warnings.filterwarnings("ignore")

    for name in (
        "httpx",
        "httpcore",
        "openai",
        "openai._base_client",
        "azure",
        "urllib3",
    ):
        noisy = logging.getLogger(name)
        noisy.setLevel(level)
        noisy.propagate = False
    warnings_logger = logging.getLogger("py.warnings")
    warnings_logger.setLevel(level)
    warnings_logger.propagate = True


def workflow_debug_context(args):
    path_override = getattr(args, "log_workflow_debug_path", None)
    if not getattr(args, "log_workflow_debug", False) and not path_override:
        return contextlib.nullcontext(None)
    metadata = build_run_metadata(
        argv=list(sys.argv),
        metis_version=METIS_VERSION,
        codebase_path=getattr(args, "codebase_path", None),
        config={
            "backend": getattr(args, "backend", None),
            "config_path": getattr(args, "config", None),
            "log_level": getattr(args, "log_level", None),
            "interactive": getattr(args, "interactive", False),
        },
    )
    return open_runlog(
        RunLogConfig(path=path_override, content="full"),
        metadata=metadata,
    )


def print_console(message, quiet=False, **kwargs):
    if quiet:
        return
    try:
        console.print(message, **kwargs)
    except MarkupError:
        fallback_kwargs = dict(kwargs)
        fallback_kwargs["markup"] = False
        console.print(str(message), **fallback_kwargs)


def _usage_triplet(summary):
    if not isinstance(summary, dict):
        return 0, 0, 0
    input_tokens = int(summary.get("input_tokens") or 0)
    output_tokens = int(summary.get("output_tokens") or 0)
    total_tokens = int(summary.get("total_tokens") or (input_tokens + output_tokens))
    return input_tokens, output_tokens, total_tokens


def _format_usage_triplet(summary):
    input_tokens, output_tokens, total_tokens = _usage_triplet(summary)
    return (
        f"(input: {input_tokens:,} · "
        f"output: {output_tokens:,} · "
        f"total: {total_tokens:,})"
    )


def _iter_operation_summaries(summary):
    if not isinstance(summary, dict):
        return []
    by_operation = summary.get("by_operation")
    if not isinstance(by_operation, dict):
        return []
    items = [
        (str(name), op_summary)
        for name, op_summary in by_operation.items()
        if isinstance(op_summary, dict) and _usage_triplet(op_summary)[2] > 0
    ]
    return sorted(
        items,
        key=lambda item: (-_usage_triplet(item[1])[2], item[0]),
    )


def _print_operation_breakdown(summary, quiet=False):
    items = _iter_operation_summaries(summary)
    if len(items) <= 1:
        return
    print_console("[bold]Breakdown by operation[/bold]", quiet=quiet)
    for operation_name, operation_summary in items:
        print_console(
            f"- {escape(operation_name)} {_format_usage_triplet(operation_summary)}",
            quiet=quiet,
        )


def print_usage_summary(command_label, current_summary, total_summary, quiet=False):
    print_console(
        f"[bold cyan]Token usage ({escape(str(command_label))})[/bold cyan]",
        quiet=quiet,
    )
    print_console(
        f"Current {_format_usage_triplet(current_summary)}",
        quiet=quiet,
    )
    _print_operation_breakdown(current_summary, quiet=quiet)


def print_final_usage_summary(
    total_summary,
    saved_path=None,
    quiet=False,
    *,
    include_totals=True,
):
    if include_totals:
        print_console("[bold cyan]Session token usage[/bold cyan]", quiet=quiet)
        print_console(
            f"Run total {_format_usage_triplet(total_summary)}",
            quiet=quiet,
        )
        _print_operation_breakdown(total_summary, quiet=quiet)
    if saved_path:
        print_console(
            f"[blue]Usage saved to {escape(str(saved_path))}[/blue]",
            quiet=quiet,
        )


def with_spinner(task_description, fn, *args, quiet=False, **kwargs):
    """
    Run a function optionally displaying a spinner.
    When quiet=True, suppress any spinner.
    """
    if quiet:
        return fn(*args, **kwargs)

    with Progress(
        SpinnerColumn(), TextColumn("[bold cyan]{task.description}"), console=console
    ) as progress:
        task = progress.add_task(task_description, total=None)
        result = fn(*args, **kwargs)
        progress.update(task, completed=1)
        progress.stop()
    return result


def with_timer(task_description, fn, *args, quiet=False, **kwargs):
    """
    Run a function while showing an elapsed-time timer.
    Shown only when quiet=False (e.g., verbose mode). In quiet=True, runs silently.
    """
    if quiet:
        return fn(*args, **kwargs)

    with Progress(
        TextColumn("[bold cyan]{task.description}"),
        TextColumn("[bright_black]elapsed"),
        TimeElapsedColumn(),
        transient=True,
        console=console,
        redirect_stdout=True,
        redirect_stderr=True,
    ) as progress:
        task = progress.add_task(task_description, total=1)
        result = fn(*args, **kwargs)
        try:
            progress.update(task, completed=1)
        except Exception:
            pass
    return result


def iterate_with_progress(total, iterable):
    results = []
    if total <= 0:
        return results
    with build_standard_progress(transient=True) as progress:
        task = progress.add_task("", total=total)
        for item in iterable:
            if item is not None:
                results.append(item)
            progress.advance(task, 1)
        try:
            progress.update(task, completed=progress.tasks[task].total)
        except Exception:
            pass
    return results


def build_standard_progress(*, transient: bool):
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("{task.description}"),
        BarColumn(bar_width=None, complete_style="green", finished_style="green"),
        TaskProgressColumn(),
        TextColumn("[bright_black]elapsed"),
        TimeElapsedColumn(),
        TextColumn("[bright_black]eta"),
        TimeRemainingColumn(),
        transient=transient,
        console=console,
        redirect_stdout=True,
        redirect_stderr=True,
    )


def count_index_items(engine):
    """Count total items to index via the indexing domain surface."""
    return engine.indexing.count_index_items()


def output_format(output_file: str | Path) -> str:
    suffix = Path(output_file).suffix.lower()
    return suffix.removeprefix(".") if suffix in {".html", ".csv", ".sarif"} else "json"


def output_files_for_formats(
    output_files: list[str] | None,
    formats: tuple[str, ...],
    *,
    command: str,
    generated_output: bool = False,
    reserved_paths: set[Path] | None = None,
) -> list[str]:
    configured = tuple(dict.fromkeys(formats))
    provided = list(output_files or ())
    if provided:
        base = Path(provided[0]).with_suffix("")
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = Path("results") / f"{command}_{timestamp}"

    selected = [] if generated_output else provided
    selected_paths = {Path(path).resolve() for path in selected}
    if len(selected_paths) != len(selected):
        raise ValueError("Output paths must be unique")
    reserved = {path.resolve() for path in reserved_paths or set()}
    if selected_paths & reserved:
        raise ValueError("Output paths for graph stages must be distinct")
    for path in selected:
        format_name = output_format(path)
        if format_name not in configured:
            raise ValueError(f"Execution graph did not request {format_name} output")

    selected_formats = {output_format(path) for path in selected}
    fallback_base: Path | None = None
    for format_name in configured:
        if format_name in selected_formats:
            continue
        candidate = base.with_suffix(f".{format_name}")
        if candidate.resolve() in reserved:
            if fallback_base is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                fallback_base = Path("results") / f"{command}_{timestamp}"
            candidate = fallback_base.with_suffix(f".{format_name}")
        if candidate.resolve() in reserved or candidate.resolve() in selected_paths:
            raise ValueError("Output paths for graph stages must be distinct")
        selected.append(str(candidate))
        selected_paths.add(candidate.resolve())
    return selected


def _record_output_artifact(path: str | Path, format_name: str) -> None:
    output_path = Path(path).resolve()
    with output_path.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    runlog.event(
        "artifact.written",
        {
            "kind": "output_file",
            "format": format_name,
            "path": str(output_path),
            "bytes": output_path.stat().st_size,
            "sha256": digest,
        },
    )


def save_output(
    output_files,
    data,
    quiet=False,
    sarif_payload=None,
):
    if not output_files:
        return

    if isinstance(output_files, (str, Path)):
        files = [output_files]
    else:
        files = list(output_files)
    json_payload = (
        apply_triage_annotations(data, sarif_payload)
        if sarif_payload is not None
        else data
    )
    sarif_payload_local = sarif_payload

    def _write_payload(path: Path, payload: object, label: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        write_json_atomic(path, payload, indent=4)
        _record_output_artifact(path, output_format(path))
        print_console(
            f"[blue]{label} saved to {escape(str(path))}[/blue]",
            quiet,
        )

    for file_entry in files:
        output_path = Path(file_entry)
        suffix = output_path.suffix.lower()

        if suffix == ".html":
            html_path = export_html(
                json_payload, output_path, REPORT_TEMPLATE, METIS_VERSION
            )
            print_console(
                f"[blue]HTML report saved to {escape(str(html_path))}[/blue]",
                quiet,
            )
            _record_output_artifact(html_path, "html")
            continue

        if suffix == ".sarif":
            sarif_path, sarif_payload_local = export_sarif(
                data, output_path, sarif_payload_local
            )
            print_console(
                f"[blue]SARIF report saved to {escape(str(sarif_path))}[/blue]",
                quiet,
            )
            _record_output_artifact(sarif_path, "sarif")
            continue

        if suffix == ".csv":
            csv_path = export_csv(json_payload, output_path)
            print_console(
                f"[blue]CSV report saved to {escape(str(csv_path))}[/blue]",
                quiet,
            )
            _record_output_artifact(csv_path, "csv")
            continue

        # default to JSON
        _write_payload(output_path, json_payload, "Results")


def check_file_exists(file_path, quiet=False):
    if not Path(file_path).is_file():
        print_console(f"[red]File not found:[/red] {escape(file_path)}", quiet)
        return False
    return True


def check_dir_exists(dir_path, quiet=False):
    if not Path(dir_path).is_dir():
        print_console(f"[red]Directory not found:[/red] {escape(dir_path)}", quiet)
        return False
    return True


def pretty_print_reviews(results, quiet=False):
    if not results or not results.get("reviews"):
        print_console("[bold green]No security issues found![/bold green]", quiet)
        return

    for file_review in results.get("reviews", []):
        file = file_review.get("file", "UNKNOWN FILE")
        reviews = file_review.get("reviews", [])
        if reviews:
            print_console(f"\n[bold blue]File: {escape(file)}[/bold blue]", quiet)
            for idx, r in enumerate(reviews, 1):
                print_console(
                    f" [yellow]Identified issue {idx}:[/yellow] [bold]{escape(r.get('issue', '-'))}[/bold]",
                    quiet,
                )
                if r.get("code_snippet"):
                    print_console(
                        f"    [cyan]Snippet:[/cyan] [dim]{r['code_snippet']}",
                        quiet,
                    )
                if r.get("line_number"):
                    print_console(
                        f"    [cyan]Line number:[/cyan] {r['line_number']}",
                        quiet,
                    )
                if r.get("cwe"):
                    cwe_text = str(r["cwe"])
                    match = re.search(r"(\d+)", cwe_text)
                    if match:
                        cwe_url = f"https://cwe.mitre.org/data/definitions/{match.group(1)}.html"
                        print_console(
                            f"    [red]CWE:[/red] [link={cwe_url}]{escape(cwe_text)}[/link]",
                            quiet,
                        )
                    else:
                        print_console(
                            f"    [red]CWE:[/red] {escape(cwe_text)}",
                            quiet,
                        )
                if severity := r.get("severity"):
                    severity_color = {
                        "Low": "green",
                        "Medium": "yellow",
                        "High": "red",
                        "Critical": "magenta",
                    }.get(severity, "bright_black")
                    print_console(
                        f"    [bright_black]Severity:[/bright_black] [bold {severity_color}]{escape(severity)}[/bold {severity_color}]",
                        quiet,
                    )
                if reasoning := r.get("reasoning"):
                    print_console(f"    [white]Why:[/white] {escape(reasoning)}", quiet)
                if r.get("mitigation"):
                    print_console(
                        f"    [green]Mitigation:[/green] {escape(r['mitigation'])}",
                        quiet,
                    )
                if confidence := r.get("confidence"):
                    print_console(
                        f"    [magenta]Confidence:[/magenta] {escape(str(confidence))}",
                        quiet,
                    )
                if any(r.get(field) for field in ("confidence", "severity", "cwe")):
                    print_console("", quiet)
        else:
            print_console(f"[green]No issues in {escape(file)}[/green]", quiet)


def build_pg_backend(args, runtime, embed_model_code, embed_model_docs, quiet=False):
    if not PG_SUPPORTED:
        print_console(
            "[bold red]Postgres backend requested but not installed. Please install with:[/bold red]",
            quiet,
        )
        print_console("  uv pip install '.[postgres]'", quiet, markup=False)
        exit(1)

    connection_string = (
        f"postgresql://{runtime['pg_username']}:{runtime['pg_password']}"
        f"@{runtime['pg_host']}:{int(runtime['pg_port'])}/{runtime['pg_db_name']}"
    )
    return PGVectorStoreImpl(
        connection_string=connection_string,
        project_schema=args.project_schema,
        embed_model_code=embed_model_code,
        embed_model_docs=embed_model_docs,
        embed_dim=runtime["embed_dim"],
        query_config=retriever_query_config(runtime),
        hnsw_kwargs=runtime.get("hnsw_kwargs", {}),
        use_halfvec=bool(runtime.get("pgvector_use_halfvec", False)),
    )


def build_chroma_backend(args, runtime, embed_model_code, embed_model_docs):
    from metis.vector_store.chroma_store import ChromaStore

    return ChromaStore(
        persist_dir=args.chroma_dir,
        embed_model_code=embed_model_code,
        embed_model_docs=embed_model_docs,
        query_config=retriever_query_config(runtime),
    )


def build_qdrant_backend(
    args, runtime, embed_model_code, embed_model_docs, quiet=False
):
    try:
        from metis.vector_store.qdrant_store import QdrantStore
    except ImportError as exc:
        print_console(
            "[bold red]Qdrant backend requested but not installed. Install it with:[/bold red]",
            quiet,
        )
        print_console("  uv pip install '.[qdrant]'", quiet, markup=False)
        raise SystemExit(1) from exc

    return QdrantStore(
        url=args.qdrant_url or os.environ.get("QDRANT_URL") or "http://localhost:6333",
        api_key=os.environ.get("QDRANT_API_KEY"),
        collection_prefix=args.project_schema,
        embed_dim=runtime["embed_dim"],
        embed_model_code=embed_model_code,
        embed_model_docs=embed_model_docs,
        query_config=retriever_query_config(runtime),
    )
