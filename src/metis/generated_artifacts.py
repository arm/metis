# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from contextlib import closing
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import time

from metis.utils import resolve_path_within_root


def _fingerprint(path: Path) -> str:
    metadata = path.stat()
    return ":".join(
        str(value)
        for value in (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
    )


@contextmanager
def generated_artifact_publication(
    codebase_path: str | Path | None, output_path: str | Path
):
    if codebase_path is None:
        yield
        return
    root = Path(codebase_path).expanduser().resolve()
    output = Path(output_path)
    try:
        output = resolve_path_within_root(root, output.parent.resolve()) / output.name
    except ValueError:
        yield
        return
    database = root / ".metis/generated_artifacts.sqlite3"
    if database.is_symlink():
        raise OSError(f"Refusing symlinked generated artifact registry: {database}")
    database = resolve_path_within_root(root, database)
    database.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database, timeout=5)) as connection:
        database.chmod(0o600)
        connection.execute(
            "CREATE TABLE IF NOT EXISTS generated_artifacts "
            "(path TEXT PRIMARY KEY, signature TEXT NOT NULL)"
        )
        connection.commit()
        connection.execute("BEGIN IMMEDIATE")
        columns = [
            (column[1], column[2], column[3], column[5])
            for column in connection.execute("PRAGMA table_info(generated_artifacts)")
        ]
        if columns != [("path", "TEXT", 0, 1), ("signature", "TEXT", 1, 0)]:
            raise ValueError(f"Incompatible generated artifact registry: {database}")
        previous = _fingerprint(output) if output.exists() else None
        failure = None
        try:
            yield
        except BaseException as exc:
            failure = exc
            raise
        finally:
            try:
                signature = _fingerprint(output) if output.exists() else None
                if signature is not None and (failure is None or signature != previous):
                    connection.execute(
                        "INSERT INTO generated_artifacts VALUES (?, ?) "
                        "ON CONFLICT(path) DO UPDATE SET signature=excluded.signature",
                        (output.relative_to(root).as_posix(), signature),
                    )
                    connection.commit()
            except BaseException as exc:
                if failure is None:
                    raise
                failure.add_note(f"Recording generated artifact also failed: {exc}")


def generated_artifact_paths(
    codebase_path: str | Path, *, timeout_seconds: float = 5.0
) -> frozenset[Path]:
    deadline = time.monotonic() + timeout_seconds
    if timeout_seconds <= 0:
        raise TimeoutError("Generated artifact lookup timed out")
    root = Path(codebase_path).expanduser().resolve()
    database = resolve_path_within_root(root, ".metis/generated_artifacts.sqlite3")
    if not database.exists():
        return frozenset()
    paths = set()
    with closing(
        sqlite3.connect(
            f"{database.as_uri()}?mode=ro", uri=True, timeout=min(5.0, timeout_seconds)
        )
    ) as connection:
        connection.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
        rows = connection.execute(
            "SELECT substr(path, 1, 4097), substr(signature, 1, 256) "
            "FROM generated_artifacts LIMIT 10001"
        )
        for index, (relative_path, signature) in enumerate(rows):
            if time.monotonic() >= deadline:
                raise TimeoutError("Generated artifact lookup timed out")
            if index == 10000:
                raise ValueError("Generated artifact registry exceeds 10000 paths")
            if not isinstance(relative_path, str) or len(relative_path) > 4096:
                continue
            try:
                path = resolve_path_within_root(root, root / relative_path)
                if _fingerprint(path) == signature:
                    paths.add(path)
            except (OSError, ValueError):
                continue
    return frozenset(paths)
