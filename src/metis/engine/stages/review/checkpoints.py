# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from concurrent.futures import CancelledError
from threading import Lock
from threading import RLock
from typing import Any

from metis.engine.execution.contracts import NodeCallbacks
from metis.version import __version__ as METIS_VERSION


class ReviewCheckpointSession:
    def __init__(self, producer: str, callbacks: NodeCallbacks) -> None:
        self._producer = producer
        self._callback = callbacks.checkpoint
        self._lock = Lock()
        self._write_lock = RLock()
        self._pending: deque[tuple[dict[str, Any], int]] = deque()
        self._records: dict[str, dict[str, Any]] = {}
        if callbacks.resume is None:
            return
        try:
            records = callbacks.resume(producer)
            if isinstance(records, Mapping):
                for key, record in records.items():
                    if isinstance(key, str) and isinstance(record, Mapping):
                        try:
                            self._records[key] = dict(record)
                        except CancelledError:
                            raise
                        except Exception:
                            continue
        except CancelledError:
            raise
        except Exception:
            return

    def get(self, key: str) -> Mapping[str, Any] | None:
        with self._lock:
            record = self._records.get(key)
            return dict(record) if record is not None else None

    def put(self, key: str, record: Mapping[str, Any]) -> None:
        # Keep durable writes in session order without locking out callback reads.
        with self._write_lock:
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
            # Keep the active entry queued so reentrant puts only append.
            self._pending.append((checkpoint, count))
            if len(self._pending) > 1:
                return
            try:
                while self._pending:
                    checkpoint, count = self._pending[0]
                    try:
                        self._callback(checkpoint, count, count)
                    except CancelledError:
                        raise
                    except Exception:
                        pass
                    self._pending.popleft()
            finally:
                self._pending.clear()

    @property
    def has_records(self) -> bool:
        with self._lock:
            return bool(self._records)
