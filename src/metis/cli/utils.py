# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import importlib.metadata
import re
from pathlib import Path
from importlib.resources import files

from rich.console import Console
from rich.markup import escape
from rich.progress import Progress, SpinnerColumn, TextColumn

from .exporters import export_csv, export_html, export_sarif

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

    logger.setLevel(logging.DEBUG)  # Capture everything; handlers will filter

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if getattr(args, "log_file", None):
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    if getattr(args, "log_level", None):
        level = getattr(logging, args.log_level.upper(), None)
        if level:
            logger.setLevel(level)


def print_console(message, quiet=False, **kwargs):
    if not quiet:
        console.print(message, **kwargs)


def with_spinner(task_description, fn, *args, **kwargs):
    with Progress(
        SpinnerColumn(), TextColumn("[bold cyan]{task.description}"), console=console
    ) as progress:
        task = progress.add_task(task_description, total=None)
        result = fn(*args, **kwargs)
        progress.update(task, completed=1)
        progress.stop()
    return result


def save_output(output_files, data, quiet=False):
    if not output_files:
        return

    if isinstance(output_files, (str, Path)):
        files = [output_files]
    else:
        files = list(output_files)
    json_payload = data
    sarif_payload = None

    def _write_payload(path: Path, payload, label: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4)
        print_console(
            f"[blue]{label} saved to {escape(str(path))}[/blue]",
            quiet,
        )

    for file_entry in files:
        output_path = Path(file_entry)
        suffix = output_path.suffix.lower()

        if suffix == ".html":
            try:
                html_path = export_html(data, output_path, REPORT_TEMPLATE, METIS_VERSION)
                print_console(
                    f"[blue]HTML report saved to {escape(str(html_path))}[/blue]",
                    quiet,
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("Failed to generate HTML report: %s", exc)
                print_console("[red]Failed to generate HTML report.[/red]", quiet)
            continue

        if suffix == ".sarif":
            try:
                sarif_path, sarif_payload = export_sarif(
                    data, output_path, sarif_payload
                )
                print_console(
                    f"[blue]SARIF report saved to {escape(str(sarif_path))}[/blue]",
                    quiet,
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("Failed to generate SARIF report: %s", exc)
                print_console(
                    f"[red]Failed to generate SARIF report at {escape(str(output_path))}[/red]",
                    quiet,
                )
            continue

        if suffix == ".csv":
            try:
                csv_path = export_csv(data, output_path)
                print_console(
                    f"[blue]CSV report saved to {escape(str(csv_path))}[/blue]",
                    quiet,
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("Failed to generate CSV report: %s", exc)
                print_console(
                    f"[red]Failed to generate CSV report at {escape(str(output_path))}[/red]",
                    quiet,
                )
            continue

        # default to JSON
        _write_payload(output_path, json_payload, "Results")


def check_file_exists(file_path, quiet=False):
    if not Path(file_path).is_file():
        print_console(f"[red]File not found:[/red] {escape(file_path)}", quiet)
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
                    f" [yellow]Identified issue {idx}:[/yellow] [bold]{escape(r.get('issue','-'))}[/bold]",
                    quiet,
                )
                if r.get("code_snippet"):
                    print_console(
                        f"    [cyan]Snippet:[/cyan] [dim]{(r['code_snippet'][:100] + '...') if len(r['code_snippet']) > 100 else r['code_snippet']}",
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
        hnsw_kwargs=runtime.get("hnsw_kwargs", {}),
    )


def build_chroma_backend(args, runtime, embed_model_code, embed_model_docs):
    from metis.vector_store.chroma_store import ChromaStore

    return ChromaStore(
        persist_dir=args.chroma_dir,
        embed_model_code=embed_model_code,
        embed_model_docs=embed_model_docs,
        query_config=runtime.get("query", {}),
    )
