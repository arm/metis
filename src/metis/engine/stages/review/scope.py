# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.engine.repository import EngineRepository

from .models import ReviewCommand


def select_review_targets(
    repository: EngineRepository,
    command: ReviewCommand,
) -> tuple[str, ...]:
    if command.mode == "code":
        return tuple(
            repository.get_code_files(
                include_suffixed_sources=True,
                dir_path=None,
            )
        )
    if command.mode == "dir":
        return tuple(
            repository.get_code_files(
                include_suffixed_sources=True,
                dir_path=command.target,
            )
        )
    if command.mode == "file":
        return (str(command.target),)
    raise ValueError(f"Review mode {command.mode!r} does not select source files")
