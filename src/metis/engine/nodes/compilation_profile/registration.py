# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import cast

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from metis import runlog
from metis.engine.execution.contracts import NodeInvocation
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.repository import EngineRepository
from metis.engine.source import ProfiledSourceReference

from .database import load_compilation_database
from .service import build_profiled_source


class CompilationProfileConfiguration(BaseModel):
    compile_commands_path: str = Field(min_length=1)
    timeout_seconds: int = Field(default=60, ge=1)

    model_config = ConfigDict(extra="forbid", frozen=True)


def create_node(repository: EngineRepository) -> NodeRegistration:
    def execute(invocation: NodeInvocation) -> NodeResult:
        configuration = cast(CompilationProfileConfiguration, invocation.configuration)
        database = load_compilation_database(
            codebase_path=invocation.context.codebase_path,
            compile_commands_path=configuration.compile_commands_path,
            include_source=lambda path: (
                repository.get_language_name_for_path(path) in {"c", "cpp"}
            ),
        )
        if not database.units:
            raise ValueError("Compilation database contains no C/C++ units")
        artifact = build_profiled_source(
            codebase_path=invocation.context.codebase_path,
            database=database,
            timeout_seconds=configuration.timeout_seconds,
            jobs=invocation.context.jobs,
            progress_callback=invocation.context.report_progress,
        )
        repository.install_profiled_source(artifact)
        runlog.event(
            "artifact",
            {
                "kind": "profiled_source_snapshot",
                "payload": artifact.reference,
            },
        )
        return NodeResult({"profiled_source": artifact.reference})

    return NodeRegistration(
        name="compilation_profile",
        stage="initialize",
        configuration=CompilationProfileConfiguration,
        inputs={},
        outputs={"profiled_source": ProfiledSourceReference},
        execute=execute,
    )
