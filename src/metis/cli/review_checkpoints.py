# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from contextlib import closing
import json
from hashlib import sha256
import logging
from pathlib import Path
import sqlite3

from metis.engine.stages.review.models import ReviewCheckpointRecord
from metis.version import __version__ as METIS_VERSION


def _checkpoint_path(checkpoint_base: Path, producer: str) -> Path:
    if (
        not producer.isascii()
        or not producer.isidentifier()
        or producer != producer.lower()
        or len(producer) > 128
    ):
        # @ cannot occur in a producer identifier, so encoded and legacy names
        # cannot alias even on case-insensitive or Unicode-normalizing volumes.
        producer = "@" + sha256(producer.encode("utf-8")).hexdigest()
    return checkpoint_base.with_name(f"{checkpoint_base.name}.{producer}.sqlite3")


def _ensure_checkpoint_schema(connection: sqlite3.Connection) -> bool:
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
    return any(
        row[1] == "producer"
        for row in connection.execute("PRAGMA table_info(review_checkpoint_records)")
    )


def _connect_checkpoint(path: Path) -> sqlite3.Connection:
    if path.is_symlink():
        raise OSError(f"Refusing symlinked review checkpoint: {path}")
    return sqlite3.connect(path)


def _sqlite_records(
    path: Path, *, producer: str | None = None
) -> dict[str, dict[str, object]] | None:
    if not path.exists():
        return None
    records: dict[str, dict[str, object]] = {}
    try:
        with closing(_connect_checkpoint(path)) as connection:
            legacy = _ensure_checkpoint_schema(connection)
            query = """
                SELECT record_key, payload
                FROM review_checkpoint_records
                WHERE metis_version = ?
            """
            parameters: tuple[str, ...] = (METIS_VERSION,)
            if legacy and producer is not None:
                query += " AND producer = ?"
                parameters += (producer,)
            rows = connection.execute(query, parameters)
            for key, payload in rows:
                try:
                    record = json.loads(payload)
                except (TypeError, ValueError, RecursionError):
                    continue
                if not isinstance(record, dict):
                    continue
                records[str(key)] = record
    except (OSError, sqlite3.Error):
        return None
    return records or None


def _write_sqlite_record(path: Path, record: ReviewCheckpointRecord) -> None:
    try:
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
            if _ensure_checkpoint_schema(connection):
                connection.execute(
                    """
                    INSERT INTO review_checkpoint_records (
                        producer, metis_version, record_key, payload
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT (producer, metis_version, record_key)
                    DO UPDATE SET payload = excluded.payload
                    """,
                    (record.producer, record.metis_version, record.key, payload),
                )
            else:
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
    except (OSError, sqlite3.Error) as exc:
        logging.getLogger("metis").error(
            "Unable to save review checkpoint %s: %s", path, exc
        )


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
        return _sqlite_records(
            _checkpoint_path(checkpoint_base, producer), producer=producer
        )

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
