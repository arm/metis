# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import hashlib
import importlib.metadata
from concurrent.futures import CancelledError
from datetime import datetime
from importlib.resources import files
from pathlib import Path
from tempfile import NamedTemporaryFile
from unicodedata import normalize
from uuid import uuid4

from rich.markup import escape

from metis import runlog
from metis.generated_artifacts import generated_artifact_publication
from metis.json_io import write_json_atomic
from metis.sarif.triage import apply_triage_annotations

from .exporters import export_csv
from .exporters import export_html
from .exporters import export_sarif

try:
    METIS_VERSION = importlib.metadata.version("metis")
except importlib.metadata.PackageNotFoundError:
    METIS_VERSION = "unknown"

REPORT_TEMPLATE = (
    files("metis.cli").joinpath("report_template.html").read_text(encoding="utf-8")
)


def output_format(output_file: str | Path) -> str:
    suffix = Path(output_file).suffix.lower()
    return suffix.removeprefix(".") if suffix in {".html", ".csv", ".sarif"} else "json"


def output_path_identity(output_file: str | Path) -> Path:
    """Compare destinations using their filesystem's case and Unicode rules."""
    path = Path(output_file).resolve()
    parent = path.parent
    while not parent.exists():
        parent = parent.parent
    # Volumes on the same host can have different case rules. Probe the actual
    # destination volume; the temporary file is removed before publication.
    with NamedTemporaryFile(prefix=".metis-é-", dir=parent) as probe:
        probe_path = Path(probe.name)
        case_insensitive = probe_path.with_name(probe_path.name.swapcase()).exists()
        normalizes_unicode = probe_path.with_name(
            normalize("NFD", probe_path.name)
        ).exists()
    identity = str(path).casefold() if case_insensitive else str(path)
    return Path(normalize("NFC", identity) if normalizes_unicode else identity)


def output_files_for_formats(
    output_files: list[str] | None,
    formats: tuple[str, ...],
    *,
    command: str,
    generated_output: bool = False,
    reserved_paths: set[Path] | None = None,
    fallback_base: Path | None = None,
) -> list[str]:
    configured = tuple(dict.fromkeys(formats))
    provided = list(output_files or ())
    if provided:
        base = Path(provided[0])
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = Path("results") / f"{command}_{timestamp}_{uuid4().hex}"

    selected = [] if generated_output else provided
    selected_paths = {output_path_identity(path) for path in selected}
    if len(selected_paths) != len(selected):
        raise ValueError("Output paths must be unique")
    reserved = {output_path_identity(path) for path in reserved_paths or set()}
    if selected_paths & reserved:
        raise ValueError("Output paths for graph stages must be distinct")
    for path in selected:
        format_name = output_format(path)
        if format_name not in configured:
            raise ValueError(f"Execution graph did not request {format_name} output")

    selected_formats = {output_format(path) for path in selected}
    for format_name in configured:
        if format_name in selected_formats:
            continue
        candidate = base.with_suffix(f".{format_name}")
        identity = output_path_identity(candidate)
        if identity in reserved:
            if fallback_base is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                fallback_base = Path("results") / f"{command}_{timestamp}_{uuid4().hex}"
            candidate = fallback_base.with_suffix(f".{format_name}")
            identity = output_path_identity(candidate)
        if identity in reserved or identity in selected_paths:
            raise ValueError("Output paths for graph stages must be distinct")
        selected.append(str(candidate))
        selected_paths.add(identity)
    return selected


def _generated_stage_output_base(output_files, stage, generated_bases):
    if not output_files:
        if generated_bases is None:
            return []
        if stage not in generated_bases:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            generated_bases[stage] = str(
                Path("results") / f"graph_{stage}_{timestamp}_{uuid4().hex}.json"
            )
        return [generated_bases[stage]]
    base = Path(output_files[0])
    stem = base.stem.removeprefix("graph_")
    return [str(base.with_name(f"graph_{stage}_{stem}"))]


def graph_output_files(
    output_files,
    outputs,
    quiet=False,
    *,
    generated_output=False,
    partial=False,
    generated_bases=None,
):
    from .utils import print_console

    review = outputs.get("review", {})
    triage_result = outputs.get("triage", {})
    findings = review.get("findings")
    review_sarif = review.get("sarif")
    triage_sarif = triage_result.get("sarif")
    review_formats = tuple(review.get("formats", ()))
    triage_formats = tuple(triage_result.get("formats", ()))
    if partial:
        review_formats = tuple(
            name
            for name in review_formats
            if (review_sarif is not None if name == "sarif" else findings is not None)
        )
        if triage_sarif is None:
            triage_formats = ()
    review_filename = review.get("filename")
    triage_filename = triage_result.get("filename")
    explicit_output = bool(output_files) and not generated_output
    if (
        not explicit_output
        and review_formats
        and triage_formats
        and review_filename is not None
        and triage_filename is not None
    ):
        review_paths = {
            output_path_identity(Path(review_filename).with_suffix(f".{fmt}"))
            for fmt in review_formats
        }
        triage_paths = {
            output_path_identity(Path(triage_filename).with_suffix(f".{fmt}"))
            for fmt in triage_formats
        }
        if review_paths & triage_paths:
            raise ValueError("Output paths for graph stages must be distinct")
    review_files: list[str] = []
    triage_files: list[str] = []
    explicit_files = (output_files or ()) if explicit_output else ()
    for path in explicit_files:
        format_name = output_format(path)
        if format_name in triage_formats:
            triage_files.append(path)
        elif format_name in review_formats:
            review_files.append(path)
        elif triage_sarif is not None:
            triage_formats = (*triage_formats, format_name)
            triage_files.append(path)
        elif (
            review_sarif is not None if format_name == "sarif" else findings is not None
        ):
            review_formats = (*review_formats, format_name)
            review_files.append(path)
        elif partial:
            print_console(
                f"[yellow]No validated {format_name} output available for "
                f"{escape(str(path))}.[/yellow]",
                quiet,
            )
        else:
            raise ValueError(f"Execution graph did not produce {format_name} output")

    if triage_formats and triage_sarif is None:
        raise ValueError("Execution graph did not produce triage results")
    if ("sarif" in review_formats and review_sarif is None) or (
        any(name != "sarif" for name in review_formats) and findings is None
    ):
        raise ValueError("Execution graph did not produce review results")
    stage_files = {"review": review_files, "triage": triage_files}
    for stage, formats, filename, other in (
        ("triage", triage_formats, triage_filename, "review"),
        ("review", review_formats, review_filename, "triage"),
    ):
        if not formats:
            continue
        selected = stage_files[stage]
        generated = not explicit_output or not selected
        if generated:
            if not explicit_output and filename is not None:
                selected = [filename]
            else:
                selected = _generated_stage_output_base(
                    output_files if not explicit_output else None,
                    stage,
                    generated_bases,
                )
        fallback = _generated_stage_output_base(None, stage, generated_bases)
        stage_files[stage] = output_files_for_formats(
            selected,
            formats,
            command=f"graph_{stage}",
            generated_output=generated,
            reserved_paths={Path(path) for path in stage_files[other]},
            fallback_base=Path(fallback[0]) if fallback else None,
        )
    return stage_files


def save_graph_outputs(
    output_files,
    outputs,
    quiet=False,
    *,
    generated_output=False,
    partial=False,
    triage_from_review=False,
    generated_bases=None,
    codebase_path=None,
    pending_error=None,
    command="graph",
):
    from .utils import pretty_print_reviews
    from .utils import print_console

    try:
        review = outputs.get("review", {})
        if command == "review":
            generated_output = generated_output or not output_files
            if generated_output and review.get("filename") is None and output_files:
                review = {**review, "filename": output_files[0]}
                outputs = {**outputs, "review": review}
        findings = review.get("findings")
        paths = graph_output_files(
            output_files,
            outputs,
            quiet,
            generated_output=generated_output,
            partial=partial or pending_error is not None,
            generated_bases=generated_bases,
        )
        if command == "review" and findings is not None:
            pretty_print_reviews(findings, quiet)
        for stage in ("review", "triage"):
            if not paths[stage]:
                continue
            values = outputs[stage]
            data = values.get("findings")
            if stage == "triage" and triage_from_review:
                data = findings
            save_output(
                paths[stage],
                data if data is not None else values.get("sarif"),
                quiet,
                sarif_payload=values.get("sarif"),
                codebase_path=codebase_path,
            )
    except CancelledError:
        raise
    except Exception as save_error:
        if pending_error is None:
            raise
        if command == "graph":
            print_console(
                f"[red]Unable to save partial outputs: {escape(str(save_error))}[/red]",
                quiet,
            )
        else:
            description = (
                "completed review" if command == "review" else "partial triage"
            )
            pending_error.add_note(
                f"Saving {description} output also failed: {save_error}"
            )
    if pending_error is not None:
        raise pending_error
    return paths


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
    *,
    codebase_path: str | Path | None = None,
):
    if not output_files:
        return

    from .utils import print_console

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

    for file_entry in files:
        output_path = Path(file_entry)
        format_name = output_format(output_path)

        with generated_artifact_publication(codebase_path, output_path):
            if format_name == "html":
                report_path = export_html(
                    json_payload, output_path, REPORT_TEMPLATE, METIS_VERSION
                )
            elif format_name == "sarif":
                report_path, sarif_payload_local = export_sarif(
                    data, output_path, sarif_payload_local
                )
            elif format_name == "csv":
                report_path = export_csv(json_payload, output_path)
            else:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                write_json_atomic(output_path, json_payload, indent=4)
                report_path = output_path
            _record_output_artifact(report_path, format_name)
            label = (
                "Results" if format_name == "json" else f"{format_name.upper()} report"
            )
            print_console(
                f"[blue]{label} saved to {escape(str(report_path))}[/blue]",
                quiet,
            )
