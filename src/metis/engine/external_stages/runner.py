# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from string import Formatter
from typing import Mapping

from .schemas import ExternalStageCommandModel


@dataclass(frozen=True, slots=True)
class ExternalStageProcessResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class ExternalStageExecutionError(RuntimeError):
    def __init__(self, message: str, *, result: ExternalStageProcessResult | None):
        super().__init__(message)
        self.result = result


class ExternalStageTimeoutError(ExternalStageExecutionError):
    pass


def command_placeholders(command: list[str]) -> set[str]:
    placeholders: set[str] = set()
    formatter = Formatter()
    for arg in command:
        for _, field_name, _, _ in formatter.parse(arg):
            if field_name:
                placeholders.add(field_name)
    return placeholders


def expand_command(
    command: list[str],
    bindings: Mapping[str, object],
) -> tuple[str, ...]:
    missing = sorted(command_placeholders(command) - set(bindings))
    if missing:
        names = ", ".join(missing)
        raise ValueError(
            f"External stage command references unknown placeholders: {names}"
        )

    rendered: list[str] = []
    for arg in command:
        rendered.append(arg.format_map({k: str(v) for k, v in bindings.items()}))
    return tuple(rendered)


class ExternalStageRunner:
    async def run(
        self,
        stage: ExternalStageCommandModel,
        *,
        bindings: Mapping[str, object],
    ) -> ExternalStageProcessResult:
        argv = expand_command(stage.command, bindings)
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise ExternalStageExecutionError(
                f"Failed to start external stage command {argv[0]!r}: {exc}",
                result=None,
            ) from exc

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=stage.timeout_seconds,
            )
        except (TimeoutError, asyncio.CancelledError) as exc:
            with suppress(ProcessLookupError):
                proc.kill()
            stdout_bytes, stderr_bytes = await proc.communicate()
            if isinstance(exc, asyncio.CancelledError):
                raise
            result = ExternalStageProcessResult(
                argv=argv,
                returncode=proc.returncode if proc.returncode is not None else -1,
                stdout=_decode(stdout_bytes),
                stderr=_decode(stderr_bytes),
            )
            raise ExternalStageTimeoutError(
                f"External stage timed out after {stage.timeout_seconds}s: {argv[0]}",
                result=result,
            ) from exc

        result = ExternalStageProcessResult(
            argv=argv,
            returncode=int(proc.returncode or 0),
            stdout=_decode(stdout_bytes),
            stderr=_decode(stderr_bytes),
        )
        if result.returncode != 0:
            raise ExternalStageExecutionError(
                f"External stage exited with status {result.returncode}: {argv[0]}",
                result=result,
            )
        return result

    def run_sync(
        self,
        stage: ExternalStageCommandModel,
        *,
        bindings: Mapping[str, object],
    ) -> ExternalStageProcessResult:
        return asyncio.run(self.run(stage, bindings=bindings))


def _decode(raw: bytes | None) -> str:
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace")
