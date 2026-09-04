# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from contextlib import closing
import json
from pathlib import Path
import sqlite3

from metis.engine.stages.review.models import ReviewCheckpointRecord
from metis.version import __version__ as METIS_VERSION


def _checkpoint_path(checkpoint_base: Path, producer: str) -> Path:
    return checkpoint_base.with_name(f"{checkpoint_base.name}.{producer}.sqlite3")


def _ensure_checkpoint_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS review_checkpoint_records (
            metis_version TEXT NOT NULL,
            record_key TEXT NOT NULL,
            payload TEXT NOT NULL,
            PRIMARY KEY (metis_version, record_key)
        ) WITHOUT ROWID
        """
    )


def _connect_checkpoint(path: Path) -> sqlite3.Connection:
    if path.is_symlink():
        raise OSError(f"Refusing symlinked review checkpoint: {path}")
    return sqlite3.connect(path)


def _discard_checkpoint(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        return


def _sqlite_records(path: Path) -> dict[str, dict[str, object]] | None:
    if not path.exists():
        return None
    records: dict[str, dict[str, object]] = {}
    try:
        with closing(_connect_checkpoint(path)) as connection:
            _ensure_checkpoint_schema(connection)
            rows = connection.execute(
                """
                SELECT record_key, payload
                FROM review_checkpoint_records
                WHERE metis_version = ?
                """,
                (METIS_VERSION,),
            )
            for key, payload in rows:
                try:
                    record = json.loads(payload)
                except (TypeError, ValueError):
                    continue
                if not isinstance(record, dict):
                    continue
                records[str(key)] = record
    except (OSError, sqlite3.Error) as exc:
        if _should_discard_on(exc):
            _discard_checkpoint(path)
        return None
    return records or None


def _write_sqlite_record_once(path: Path, record: ReviewCheckpointRecord) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        record.record,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    with closing(_connect_checkpoint(path)) as connection:
        path.chmod(0o600)
        connection.execute("PRAGMA busy_timeout = 5000")
        _ensure_checkpoint_schema(connection)
        connection.execute(
            """
            INSERT INTO review_checkpoint_records (
                metis_version, record_key, payload
            ) VALUES (?, ?, ?)
            ON CONFLICT (metis_version, record_key)
            DO UPDATE SET payload = excluded.payload
            """,
            (record.metis_version, record.key, payload),
        )
        connection.commit()


_TRANSIENT_SQLITE_CODES = frozenset({sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED})


def _should_discard_on(exc: BaseException) -> bool:
    if not isinstance(exc, sqlite3.Error):
        return False
    code = getattr(exc, "sqlite_errorcode", None)
    if code in _TRANSIENT_SQLITE_CODES:
        return False
    if code is None:
        message = str(exc).lower()
        if "locked" in message or "busy" in message:
            return False
    return True


def _write_sqlite_record(path: Path, record: ReviewCheckpointRecord) -> None:
    try:
        _write_sqlite_record_once(path, record)
    except (OSError, sqlite3.Error) as exc:
        if _should_discard_on(exc):
            _discard_checkpoint(path)
        try:
            _write_sqlite_record_once(path, record)
        except (OSError, sqlite3.Error) as retry_exc:
            if _should_discard_on(retry_exc):
                _discard_checkpoint(path)


def review_checkpoint_callbacks(
    *,
    codebase_path: str | Path,
    enabled: bool,
) -> dict[str, object]:
    if not enabled:
        return {}
    checkpoint_base = (
        Path(codebase_path).expanduser().resolve() / ".metis" / "checkpoints" / "review"
    )

    def resume(producer: str) -> Mapping[str, Mapping[str, object]] | None:
        return _sqlite_records(_checkpoint_path(checkpoint_base, producer))

    def checkpoint(
        payload: dict[str, object],
        _processed: int,
        _total: int,
    ) -> None:
        record = ReviewCheckpointRecord.model_validate(payload)
        _write_sqlite_record(
            _checkpoint_path(checkpoint_base, record.producer),
            record,
        )

    return {
        "review_checkpoint_callback": checkpoint,
        "review_resume_callback": resume,
    }
