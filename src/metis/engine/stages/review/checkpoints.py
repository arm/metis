# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping
from threading import Lock
from typing import Any

from metis.engine.execution.contracts import NodeCallbacks
from metis.version import __version__ as METIS_VERSION


class ReviewCheckpointSession:
    def __init__(self, producer: str, callbacks: NodeCallbacks) -> None:
        self._producer = producer
        self._callback = callbacks.checkpoint
        self._lock = Lock()
        self._records: dict[str, dict[str, Any]] = {}
        if callbacks.resume is None:
            return
        try:
            records = callbacks.resume(producer)
        except Exception:
            return
        if records is not None:
            self._records.update({key: dict(record) for key, record in records.items()})

    def get(self, key: str) -> Mapping[str, Any] | None:
        with self._lock:
            record = self._records.get(key)
            return dict(record) if record is not None else None

    def put(self, key: str, record: Mapping[str, Any]) -> None:
        with self._lock:
            self._records[key] = dict(record)
            if self._callback is None:
                return
            checkpoint = {
                "metis_version": METIS_VERSION,
                "producer": self._producer,
                "key": key,
                "record": dict(record),
            }
            count = len(self._records)
            try:
                self._callback(
                    checkpoint,
                    count,
                    count,
                )
            except Exception:
                return

    @property
    def has_records(self) -> bool:
        with self._lock:
            return bool(self._records)
