# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import importlib.metadata
import json
import logging
import os
import re
import warnings
from pathlib import Path
from importlib.resources import files

from rich.console import Console
from rich.errors import MarkupError
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
from metis.sarif.utils import create_fingerprint

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


def print_console(message, quiet=False, force=False, **kwargs):
    if not quiet or force:
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


def print_usage_summary(command_label, current_summary, total_summary):
    print_console(
        f"[bold cyan]Token usage ({escape(str(command_label))})[/bold cyan]",
        force=True,
    )
    print_console(
        f"Current {_format_usage_triplet(current_summary)}",
        force=True,
    )


def print_final_usage_summary(total_summary, saved_path=None):
    print_console("[bold cyan]Session token usage[/bold cyan]", force=True)
    print_console(
        f"Run total {_format_usage_triplet(total_summary)}",
        force=True,
    )
    if saved_path:
        print_console(
            f"[blue]Usage saved to {escape(str(saved_path))}[/blue]",
            force=True,
        )


def with_spinner(task_description, fn, *args, quiet=False, **kwargs):
    """
    Run a function optionally displaying a spinner.
    When quiet=True (e.g., non-interactive without --verbose), suppress any spinner.
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


def collect_reviews(engine):
    return {"reviews": [r for r in engine.review_code() if r]}


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
    """
    Count total items to index (code + docs files).
    Used to size the progress bar for verbose indexing.
    """

    docs_exts = engine.plugin_config.get("docs", {})
    code_count = len(engine.get_code_files())

    doc_count = 0
    base_path = os.path.abspath(engine.codebase_path)
    for _, _, _files in os.walk(base_path):
        for f in _files:
            if os.path.splitext(f)[1].lower() in docs_exts:
                doc_count += 1

    return code_count + doc_count


def save_output(output_files, data, quiet=False, sarif_payload=None):
    if not output_files:
        return

    if isinstance(output_files, (str, Path)):
        files = [output_files]
    else:
        files = list(output_files)
    json_payload = (
        _merge_triage_annotations(data, sarif_payload)
        if sarif_payload is not None
        else data
    )
    sarif_payload_local = sarif_payload

    def _write_payload(path, payload, label):
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
                html_path = export_html(
                    json_payload, output_path, REPORT_TEMPLATE, METIS_VERSION
                )
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
                sarif_path, sarif_payload_local = export_sarif(
                    data, output_path, sarif_payload_local
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
                csv_path = export_csv(json_payload, output_path)
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


def _merge_triage_annotations(report_data, sarif_payload):
    if not isinstance(report_data, dict):
        return report_data
    reviews = report_data.get("reviews")
    if not isinstance(reviews, list):
        return report_data
    runs = sarif_payload.get("runs") if isinstance(sarif_payload, dict) else None
    if not isinstance(runs, list):
        return report_data

    sarif_results = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if not isinstance(results, list):
            continue
        sarif_results.extend(results)

    issue_refs = []
    for file_entry in reviews:
        if not isinstance(file_entry, dict):
            continue
        file_name = str(file_entry.get("file") or file_entry.get("file_path") or "")
        issues = file_entry.get("reviews")
        if not isinstance(issues, list):
            continue
        for issue in issues:
            if isinstance(issue, dict):
                issue_refs.append((issue, file_name))

    if not sarif_results or not issue_refs:
        return report_data

    indexed = []
    fp_map: dict[str, list[int]] = {}
    file_line_issue_map: dict[tuple[str, int, str], list[int]] = {}
    file_line_map: dict[tuple[str, int], list[int]] = {}
    file_issue_map: dict[tuple[str, str], list[int]] = {}
    file_line_rule_map: dict[tuple[str, int, str], list[int]] = {}
    file_rule_issue_map: dict[tuple[str, str, str], list[int]] = {}

    for idx, result in enumerate(sarif_results):
        if not isinstance(result, dict):
            continue
        properties = result.get("properties")
        if not isinstance(properties, dict):
            continue

        file_name, line_number = _extract_sarif_location(result)
        issue_text = _extract_sarif_issue_text(result)
        rule_id = _extract_sarif_rule_id(result)
        fingerprint = _extract_sarif_fingerprint(result)
        indexed.append((idx, properties))
        if fingerprint:
            fp_map.setdefault(fingerprint, []).append(idx)
        if file_name and line_number > 0 and rule_id:
            file_line_rule_map.setdefault((file_name, line_number, rule_id), []).append(
                idx
            )
        if file_name and line_number > 0 and issue_text:
            file_line_issue_map.setdefault(
                (file_name, line_number, issue_text), []
            ).append(idx)
        if file_name and rule_id and issue_text:
            file_rule_issue_map.setdefault((file_name, rule_id, issue_text), []).append(
                idx
            )
        if file_name and line_number > 0:
            file_line_map.setdefault((file_name, line_number), []).append(idx)
        if file_name and issue_text:
            file_issue_map.setdefault((file_name, issue_text), []).append(idx)

    unused = {idx for idx, _ in indexed}

    def _take_from(mapping, key):
        entries = mapping.get(key)
        if not entries:
            return None
        while entries:
            candidate = entries.pop(0)
            if candidate in unused:
                return candidate
        return None

    properties_by_idx = {idx: props for idx, props in indexed}

    for issue, file_name in issue_refs:
        line_number = _normalize_issue_line(issue.get("line_number"))
        issue_text = str(issue.get("issue") or issue.get("title") or "").strip()
        issue_rule = str(issue.get("rule_id") or issue.get("ruleId") or "").strip()
        fingerprint = ""
        if file_name and line_number > 0:
            fingerprint = create_fingerprint(file_name, line_number, "AI001")

        matchers = []
        if fingerprint:
            matchers.append((fp_map, fingerprint))
        if file_name and line_number > 0 and issue_rule:
            matchers.append((file_line_rule_map, (file_name, line_number, issue_rule)))
        if file_name and line_number > 0 and issue_text:
            matchers.append((file_line_issue_map, (file_name, line_number, issue_text)))
        if file_name and issue_rule and issue_text:
            matchers.append((file_rule_issue_map, (file_name, issue_rule, issue_text)))
        if file_name and line_number > 0:
            matchers.append((file_line_map, (file_name, line_number)))
        if file_name and issue_text:
            matchers.append((file_issue_map, (file_name, issue_text)))

        match_idx = None
        for mapping, key in matchers:
            match_idx = _take_from(mapping, key)
            if match_idx is not None:
                break
        if match_idx is None:
            continue

        unused.discard(match_idx)
        properties = properties_by_idx.get(match_idx)
        if not properties:
            continue
        _apply_triage_properties(issue, properties)

    return report_data


def _normalize_issue_line(raw_line) -> int:
    try:
        parsed = int(raw_line)
    except Exception:
        return 1
    return parsed if parsed > 0 else 1


def _extract_sarif_fingerprint(result: dict) -> str:
    partial = result.get("partialFingerprints")
    if not isinstance(partial, dict):
        return ""
    return str(partial.get("primaryLocationLineHash") or "").strip()


def _extract_sarif_location(result: dict) -> tuple[str, int]:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return "", 1
    first = locations[0]
    if not isinstance(first, dict):
        return "", 1
    physical = first.get("physicalLocation")
    if not isinstance(physical, dict):
        return "", 1
    artifact = physical.get("artifactLocation")
    file_name = ""
    if isinstance(artifact, dict):
        file_name = str(artifact.get("uri") or "")
    region = physical.get("region")
    properties = result.get("properties")
    if isinstance(properties, dict):
        reported_line = properties.get("reportedLineNumber")
        if reported_line is not None:
            return file_name, _normalize_issue_line(reported_line)
    if not isinstance(region, dict):
        return file_name, 1
    return file_name, _normalize_issue_line(region.get("startLine"))


def _extract_sarif_rule_id(result: dict) -> str:
    return str(result.get("ruleId") or "").strip()


def _extract_sarif_issue_text(result: dict) -> str:
    message = result.get("message")
    if isinstance(message, dict):
        return str(message.get("text") or "").strip()
    if isinstance(message, str):
        return message.strip()
    return ""


def _apply_triage_properties(issue: dict, properties: dict) -> None:
    if "metisTriaged" in properties:
        issue["metisTriaged"] = bool(properties.get("metisTriaged"))
    if "metisTriageStatus" in properties:
        issue["metisTriageStatus"] = str(properties.get("metisTriageStatus") or "")
    if "metisTriageReason" in properties:
        issue["metisTriageReason"] = str(properties.get("metisTriageReason") or "")
    if "metisTriageTimestamp" in properties:
        issue["metisTriageTimestamp"] = str(
            properties.get("metisTriageTimestamp") or ""
        )


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
