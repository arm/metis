# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
from datetime import datetime
import json
from pathlib import Path
import re
import sqlite3
from threading import RLock
from typing import Any, Iterable

from langgraph.store.base import BaseStore
from langgraph.store.base import GetOp
from langgraph.store.base import Item
from langgraph.store.base import ListNamespacesOp
from langgraph.store.base import Op
from langgraph.store.base import PutOp
from langgraph.store.base import Result
from langgraph.store.base import SearchItem
from langgraph.store.base import SearchOp

from .schemas import utc_now_iso
from .sqlite_records import fts_column_values
from .sqlite_records import MemoryRecordsTable


class SQLiteMemoryStore(BaseStore):
    supports_ttl = False

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._records = MemoryRecordsTable()
        self._lock = RLock()
        self._initialized = False
        self._fts_enabled = False

    def batch(self, ops: Iterable[Op]) -> list[Result]:
        with self._lock:
            self._ensure_schema()
            with self._connect() as conn:
                results = [self._execute_op(conn, op) for op in ops]
                conn.commit()
                return results

    async def abatch(self, ops: Iterable[Op]) -> list[Result]:
        return await asyncio.to_thread(self.batch, list(ops))

    def _execute_op(self, conn: sqlite3.Connection, op: Op) -> Result:
        if isinstance(op, PutOp):
            if op.value is None:
                self._delete(conn, op.namespace, op.key)
            else:
                self._put(conn, op.namespace, op.key, op.value)
            return None
        if isinstance(op, GetOp):
            return self._get(conn, op.namespace, op.key)
        if isinstance(op, SearchOp):
            return self._search(
                conn,
                op.namespace_prefix,
                query=op.query,
                filter=op.filter,
                limit=op.limit,
                offset=op.offset,
            )
        if isinstance(op, ListNamespacesOp):
            return self._list_namespaces(
                conn,
                match_conditions=op.match_conditions,
                max_depth=op.max_depth,
                limit=op.limit,
                offset=op.offset,
            )
        raise TypeError(f"Unsupported memory store operation: {type(op).__name__}")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout = 5000")
            conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.DatabaseError:
            pass
        return conn

    def _ensure_schema(self) -> None:
        if self._initialized:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            self._records.ensure_schema(conn)
            self._fts_enabled = self._records.ensure_fts(conn)
            conn.commit()
        self._initialized = True

    def _put(
        self,
        conn: sqlite3.Connection,
        namespace: tuple[str, ...],
        key: str,
        value: dict[str, Any],
    ) -> None:
        namespace_json = _encode_namespace(namespace)
        now = utc_now_iso()
        existing_created_at = self._records.created_at(
            conn,
            namespace_json=namespace_json,
            key=key,
        )
        created_at = existing_created_at or now
        value_to_store = dict(value)
        value_to_store.pop("created_at", None)
        value_json = json.dumps(value_to_store, sort_keys=True, separators=(",", ":"))
        self._records.upsert(
            conn,
            namespace_json=namespace_json,
            key=key,
            value_json=value_json,
            created_at=created_at,
            updated_at=now,
        )
        if self._fts_enabled:
            self._records.upsert_fts(
                conn,
                namespace_json=namespace_json,
                key=key,
                values=fts_column_values(value_to_store),
            )

    def _delete(
        self,
        conn: sqlite3.Connection,
        namespace: tuple[str, ...],
        key: str,
    ) -> None:
        namespace_json = _encode_namespace(namespace)
        self._records.delete(
            conn,
            namespace_json=namespace_json,
            key=key,
            include_fts=self._fts_enabled,
        )

    def _get(
        self,
        conn: sqlite3.Connection,
        namespace: tuple[str, ...],
        key: str,
    ) -> Item | None:
        row = self._records.get(
            conn,
            namespace_json=_encode_namespace(namespace),
            key=key,
        )
        if row is None:
            return None
        return _item_from_row(row)

    def _search(
        self,
        conn: sqlite3.Connection,
        namespace_prefix: tuple[str, ...],
        *,
        query: str | None,
        filter: dict[str, Any] | None,
        limit: int,
        offset: int,
    ) -> list[SearchItem]:
        rows = self._candidate_rows(conn, query)
        matches: list[SearchItem] = []
        for row in rows:
            namespace = _decode_namespace(str(row["namespace"]))
            if not _namespace_startswith(namespace, namespace_prefix):
                continue
            value = json.loads(str(row["value_json"]))
            if not _matches_filter(value, filter):
                continue
            matches.append(_search_item_from_row(row, value=value))
        matches.sort(key=lambda item: (item.namespace, item.key))
        return matches[max(0, offset) : max(0, offset) + max(0, limit)]

    def _candidate_rows(
        self,
        conn: sqlite3.Connection,
        query: str | None,
    ) -> list[sqlite3.Row]:
        if not query:
            return self._records.rows(conn)
        fts_query = _fts_query(query)
        if not fts_query:
            return []
        if not self._fts_enabled:
            raise RuntimeError("SQLite FTS5 is required for memory text search.")
        return self._records.fts_rows(conn, query=fts_query)

    def _list_namespaces(
        self,
        conn: sqlite3.Connection,
        *,
        match_conditions,
        max_depth: int | None,
        limit: int,
        offset: int,
    ) -> list[tuple[str, ...]]:
        rows = self._records.distinct_namespaces(conn)
        namespaces: set[tuple[str, ...]] = set()
        for row in rows:
            namespace = _decode_namespace(str(row["namespace"]))
            if not _matches_namespace_conditions(namespace, match_conditions):
                continue
            if max_depth is not None:
                namespace = namespace[: max(0, int(max_depth))]
            namespaces.add(namespace)
        ordered = sorted(namespaces)
        return ordered[max(0, offset) : max(0, offset) + max(0, limit)]


def _item_from_row(row: sqlite3.Row) -> Item:
    return Item(
        namespace=_decode_namespace(str(row["namespace"])),
        key=str(row["key"]),
        value=json.loads(str(row["value_json"])),
        created_at=_parse_datetime(str(row["created_at"])),
        updated_at=_parse_datetime(str(row["updated_at"])),
    )


def _search_item_from_row(
    row: sqlite3.Row,
    *,
    value: dict[str, Any],
) -> SearchItem:
    return SearchItem(
        namespace=_decode_namespace(str(row["namespace"])),
        key=str(row["key"]),
        value=value,
        created_at=_parse_datetime(str(row["created_at"])),
        updated_at=_parse_datetime(str(row["updated_at"])),
        score=None,
    )


def _encode_namespace(namespace: tuple[str, ...]) -> str:
    return json.dumps(list(namespace), separators=(",", ":"))


def _decode_namespace(value: str) -> tuple[str, ...]:
    raw = json.loads(value)
    return tuple(str(part) for part in raw)


def _namespace_startswith(
    namespace: tuple[str, ...],
    prefix: tuple[str, ...],
) -> bool:
    return namespace[: len(prefix)] == prefix


def _matches_namespace_conditions(namespace, match_conditions) -> bool:
    if not match_conditions:
        return True
    for condition in match_conditions:
        path = tuple(str(part) for part in condition.path)
        if condition.match_type == "prefix" and not _namespace_startswith(
            namespace, path
        ):
            return False
        if condition.match_type == "suffix" and namespace[-len(path) :] != path:
            return False
    return True


def _matches_filter(value: dict[str, Any], filter_value: dict[str, Any] | None) -> bool:
    if not filter_value:
        return True
    for key, expected in filter_value.items():
        if _value_at_path(value, str(key).split(".")) != expected:
            return False
    return True


def _value_at_path(value: Any, path: list[str]) -> Any:
    current = value
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _fts_query(query: str) -> str:
    return " ".join(_query_terms(query))


def _query_terms(query: str) -> list[str]:
    return [term.lower() for term in re.findall(r"[A-Za-z0-9_]+", query)]


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
