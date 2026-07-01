# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from datetime import timezone
from typing import Any

from metis.version import __version__ as METIS_VERSION

from .base import Namespace
from .base import StoreLike
from .schemas import MemoryRecord


class MemoryService:
    def __init__(
        self,
        store: StoreLike,
        *,
        repo_root: str = "",
        tool_version: str = METIS_VERSION,
    ):
        self.store = store
        self.repo_root = repo_root
        self.tool_version = tool_version

    def put_record(self, record: MemoryRecord) -> None:
        self.store.put(record.namespace, record.key, record.to_store_value())

    def create_record(
        self,
        *,
        namespace: Namespace,
        key: str,
        **value: Any,
    ) -> MemoryRecord:
        record = MemoryRecord.create(
            namespace=namespace,
            key=key,
            tool_version=self.tool_version,
            **value,
        )
        self.put_record(record)
        return self.get_record(namespace, key) or record

    def get_record(self, namespace: Namespace, key: str) -> MemoryRecord | None:
        item = self.store.get(namespace, key)
        if item is None:
            return None
        return _record_from_item(item)

    def search_records(
        self,
        namespace_prefix: Namespace,
        *,
        query: str | None = None,
        filter: dict[str, Any] | None = None,
        limit: int = 10,
        offset: int = 0,
    ) -> list[MemoryRecord]:
        items = self.store.search(
            namespace_prefix,
            query=query,
            filter=filter,
            limit=limit,
            offset=offset,
        )
        return _records_from_items(items)

    def iter_records(
        self,
        namespace_prefix: Namespace = (),
        *,
        query: str | None = None,
        filter: dict[str, Any] | None = None,
        batch_size: int = 500,
    ) -> Iterator[MemoryRecord]:
        offset = 0
        batch_size = max(1, int(batch_size or 500))
        while True:
            items = self.store.search(
                namespace_prefix,
                query=query,
                filter=filter,
                limit=batch_size,
                offset=offset,
            )
            records = _records_from_items(items)
            yield from records
            if len(items) < batch_size:
                return
            offset += batch_size

    def invalidate(self, namespace: Namespace, key: str) -> None:
        self.store.delete(namespace, key)

    def reset_records(
        self,
        namespace_prefix: Namespace = (),
    ) -> int:
        records = list(self.iter_records(namespace_prefix))
        for record in records:
            self.invalidate(record.namespace, record.key)
        return len(records)

    def delete_stale_records(
        self,
        namespace_prefix: Namespace = (),
        *,
        repo_fingerprint: str | None = None,
        input_fingerprint: str | None = None,
        tool_version: str | None = None,
    ) -> int:
        if (
            repo_fingerprint is None
            and input_fingerprint is None
            and tool_version is None
        ):
            return 0
        deleted = 0
        for record in list(self.iter_records(namespace_prefix)):
            if self.is_fresh(
                record,
                repo_fingerprint=repo_fingerprint,
                input_fingerprint=input_fingerprint,
                tool_version=tool_version,
            ):
                continue
            self.invalidate(record.namespace, record.key)
            deleted += 1
        return deleted

    def is_fresh(
        self,
        record: MemoryRecord,
        *,
        repo_fingerprint: str | None = None,
        input_fingerprint: str | None = None,
        tool_version: str | None = None,
    ) -> bool:
        if repo_fingerprint is not None and record.repo_fingerprint != repo_fingerprint:
            return False
        if (
            input_fingerprint is not None
            and record.input_fingerprint != input_fingerprint
        ):
            return False
        if tool_version is not None and record.tool_version != tool_version:
            return False
        return True


def _record_from_item(item: Any) -> MemoryRecord:
    return MemoryRecord.from_store_value(
        namespace=item.namespace,
        key=item.key,
        value=item.value,
        created_at=_datetime_to_iso(item.created_at),
    )


def _records_from_items(items: list[Any]) -> list[MemoryRecord]:
    return [_record_from_item(item) for item in items]


def _datetime_to_iso(value: object) -> str:
    if not isinstance(value, datetime):
        raise TypeError(f"Expected datetime, got {type(value).__name__}")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")
