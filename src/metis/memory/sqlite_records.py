# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sqlite3
from typing import Any

_FTS_COLUMNS = ("artifact_type", "summary_text", "search_text")


def fts_column_values(record_value: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(record_value.get(column) or "") for column in _FTS_COLUMNS)


class MemoryRecordsTable:
    def ensure_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_records (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                value_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (namespace, key)
            )
            """
        )

    def ensure_fts(self, conn: sqlite3.Connection) -> bool:
        conn.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS memory_records_fts
            USING fts5(namespace, key, artifact_type, summary_text, search_text)
            """
        )
        return True

    def created_at(
        self,
        conn: sqlite3.Connection,
        *,
        namespace_json: str,
        key: str,
    ) -> str | None:
        row = conn.execute(
            "SELECT created_at FROM memory_records WHERE namespace = ? AND key = ?",
            (namespace_json, key),
        ).fetchone()
        if row is None:
            return None
        return str(row["created_at"])

    def upsert(
        self,
        conn: sqlite3.Connection,
        *,
        namespace_json: str,
        key: str,
        value_json: str,
        created_at: str,
        updated_at: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO memory_records (
                namespace,
                key,
                value_json,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(namespace, key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at = excluded.updated_at
            """,
            (
                namespace_json,
                key,
                value_json,
                created_at,
                updated_at,
            ),
        )

    def upsert_fts(
        self,
        conn: sqlite3.Connection,
        *,
        namespace_json: str,
        key: str,
        values: tuple[str, ...],
    ) -> None:
        conn.execute(
            "DELETE FROM memory_records_fts WHERE namespace = ? AND key = ?",
            (namespace_json, key),
        )
        conn.execute(
            """
            INSERT INTO memory_records_fts (
                namespace, key, artifact_type, summary_text, search_text
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                namespace_json,
                key,
                *values,
            ),
        )

    def delete(
        self,
        conn: sqlite3.Connection,
        *,
        namespace_json: str,
        key: str,
        include_fts: bool,
    ) -> None:
        conn.execute(
            "DELETE FROM memory_records WHERE namespace = ? AND key = ?",
            (namespace_json, key),
        )
        if include_fts:
            conn.execute(
                "DELETE FROM memory_records_fts WHERE namespace = ? AND key = ?",
                (namespace_json, key),
            )

    def get(
        self,
        conn: sqlite3.Connection,
        *,
        namespace_json: str,
        key: str,
    ) -> sqlite3.Row | None:
        return conn.execute(
            """
            SELECT namespace, key, value_json, created_at, updated_at
            FROM memory_records
            WHERE namespace = ? AND key = ?
            """,
            (namespace_json, key),
        ).fetchone()

    def rows(self, conn: sqlite3.Connection) -> list[sqlite3.Row]:
        return conn.execute(
            """
            SELECT namespace, key, value_json, created_at, updated_at
            FROM memory_records
            """
        ).fetchall()

    def fts_rows(
        self,
        conn: sqlite3.Connection,
        *,
        query: str,
    ) -> list[sqlite3.Row]:
        return conn.execute(
            """
            SELECT r.namespace, r.key, r.value_json, r.created_at, r.updated_at
            FROM memory_records_fts f
            JOIN memory_records r
              ON r.namespace = f.namespace AND r.key = f.key
            WHERE memory_records_fts MATCH ?
            """,
            (query,),
        ).fetchall()

    def distinct_namespaces(self, conn: sqlite3.Connection) -> list[sqlite3.Row]:
        return conn.execute("SELECT DISTINCT namespace FROM memory_records").fetchall()
