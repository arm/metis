# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from rich.markup import escape

from metis.engine.stages.triage.service import TriageService

from .output import graph_output_files
from .output import output_path_identity
from .utils import print_console


def triage_checkpoint_callbacks(
    *,
    output_files: list[str],
    generated_output: bool,
    execution: Mapping[str, Any],
    checkpoint_every: int,
    quiet: bool,
    generated_bases: dict[str, str] | None = None,
    codebase_path: str | None = None,
) -> dict[str, object]:
    stages = execution.get("stages", {})
    stage = stages.get("triage")
    if stage is None or checkpoint_every <= 0:
        return {}
    configured_outputs = {}
    for name in ("review", "triage"):
        configured = stages.get(name)
        if configured is None:
            continue
        nodes = configured.get("nodes", {})
        bindings = configured.get("outputs") or {
            field: f"result.{field}" for field in ("formats", "filename")
        }
        if not isinstance(bindings, Mapping):
            bindings = {field: field for field in bindings}
        values = {"sarif": {}}
        if name == "review":
            values["findings"] = {}
        for field in ("formats", "filename"):
            source = bindings.get(field)
            if isinstance(source, str):
                value = nodes.get(source.partition(".")[0], {}).get(field)
                if value is not None:
                    values[field] = value
        configured_outputs[name] = values
    if not output_files and not configured_outputs["triage"].get("filename"):
        return {}
    planned = graph_output_files(
        output_files,
        configured_outputs,
        quiet,
        generated_output=generated_output,
        generated_bases=generated_bases,
    )
    checkpoint = triage_checkpoint_path(
        planned["triage"],
        reserved_paths=[path for paths in planned.values() for path in paths],
    )
    if checkpoint is None:
        return {}
    print_console(
        f"[blue]Triage checkpoint path:[/blue] {escape(str(checkpoint))}", quiet
    )
    service = TriageService(triage_checkpoint_every=checkpoint_every)
    return {
        "checkpoint_callback": service.checkpoint_callback(
            str(checkpoint), codebase_path=codebase_path
        )
    }


def triage_checkpoint_path(
    output_files: list[str], *, reserved_paths: list[str]
) -> Path | None:
    if not output_files:
        return None
    checkpoint = Path(
        next(
            (path for path in output_files if Path(path).suffix.lower() == ".sarif"),
            output_files[0],
        )
    ).with_suffix(".checkpoint.sarif")
    if output_path_identity(checkpoint) in {
        output_path_identity(path) for path in reserved_paths
    }:
        raise ValueError("Triage checkpoint must be distinct from output paths")
    return checkpoint
