# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Read compile_commands.json and normalize its recorded compiler commands."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class CompilationUnit:
    profile_id: str
    directory: Path
    source: Path
    argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CompilationDatabase:
    path: Path
    sha256: str
    units: tuple[CompilationUnit, ...]


def load_compilation_database(
    *,
    codebase_path: str,
    compile_commands_path: str,
    include_source: Callable[[str], bool] | None = None,
) -> CompilationDatabase:
    root = Path(codebase_path).expanduser().resolve()
    path = Path(compile_commands_path).expanduser()
    path = (path if path.is_absolute() else root / path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Compilation database does not exist: {path}")
    payload = path.read_bytes()
    return CompilationDatabase(
        path,
        hashlib.sha256(payload).hexdigest(),
        _load_units(path, payload, include_source),
    )


def _load_units(
    database: Path,
    payload: bytes,
    include_source: Callable[[str], bool] | None,
) -> tuple[CompilationUnit, ...]:
    try:
        raw = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid compilation database {database}: {exc}") from exc
    if not isinstance(raw, list) or not raw:
        raise ValueError("Compilation database must contain a non-empty JSON array")
    units = (
        _load_unit(
            item,
            index=index,
            database=database,
            include_source=include_source,
        )
        for index, item in enumerate(raw)
    )
    return tuple(
        sorted(
            (unit for unit in units if unit is not None),
            key=lambda unit: unit.profile_id,
        )
    )


def _load_unit(
    raw: object,
    *,
    index: int,
    database: Path,
    include_source: Callable[[str], bool] | None,
) -> CompilationUnit | None:
    if not isinstance(raw, dict):
        raise TypeError(f"Compilation database entry {index} must be an object")
    directory_value = raw.get("directory")
    file_value = raw.get("file")
    if not isinstance(file_value, str) or not file_value.strip():
        raise ValueError(f"Compilation database entry {index} has no file")
    if include_source is not None and not include_source(file_value):
        return None
    if not isinstance(directory_value, str) or not directory_value.strip():
        raise ValueError(f"Compilation database entry {index} has no directory")

    directory = Path(directory_value).expanduser()
    directory = (
        directory if directory.is_absolute() else database.parent / directory
    ).resolve()
    if not directory.is_dir():
        raise FileNotFoundError(
            f"Compilation database entry {index} directory does not exist: {directory}"
        )
    source = Path(file_value).expanduser()
    source = (source if source.is_absolute() else directory / source).resolve()
    if not source.is_file():
        raise FileNotFoundError(
            f"Compilation database entry {index} source does not exist: {source}"
        )

    arguments = raw.get("arguments")
    command = raw.get("command")
    if (
        isinstance(arguments, list)
        and arguments
        and all(isinstance(argument, str) for argument in arguments)
    ):
        argv = tuple(arguments)
    elif isinstance(command, str) and command.strip():
        try:
            argv = tuple(shlex.split(command, posix=os.name != "nt"))
        except ValueError as exc:
            raise ValueError(
                f"Compilation database entry {index} has an invalid command"
            ) from exc
    else:
        raise ValueError(
            f"Compilation database entry {index} requires arguments or command"
        )
    executable = _resolve_executable(argv[0], directory)
    argv = (executable, *argv[1:])
    profile_payload = json.dumps(
        {"directory": str(directory), "file": str(source), "argv": argv},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return CompilationUnit(
        hashlib.sha256(profile_payload).hexdigest(),
        directory,
        source,
        argv,
    )


def _resolve_executable(value: str, directory: Path) -> str:
    candidate = Path(value).expanduser()
    if candidate.is_absolute() or candidate.parent != Path("."):
        candidate = candidate if candidate.is_absolute() else directory / candidate
        candidate = candidate.resolve()
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise FileNotFoundError(f"Compiler is not executable: {candidate}")
        return str(candidate)
    resolved = shutil.which(value)
    if resolved is None:
        raise FileNotFoundError(f"Compiler is not available on PATH: {value}")
    return resolved
