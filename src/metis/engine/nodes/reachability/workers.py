# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import logging
import threading
from typing import Any, TypeVar

from metis.usage import submit_with_current_context

logger = logging.getLogger("metis")

JobT = TypeVar("JobT")
ResultT = TypeVar("ResultT")


def coerce_worker_count(
    max_workers: int | str | None,
    *,
    default: int = 1,
) -> int:
    value = default if max_workers is None or max_workers == "" else max_workers
    return max(1, int(value))


def bounded_worker_count(max_workers: int | str | None, item_count: int) -> int:
    if item_count <= 1:
        return 1
    return min(coerce_worker_count(max_workers), item_count)


@dataclass(frozen=True, slots=True)
class ReachabilityWorkerBudget:
    total: int = 1

    def __post_init__(self):
        object.__setattr__(self, "total", coerce_worker_count(self.total))

    @classmethod
    def from_value(cls, max_workers: int | str | None):
        return cls(coerce_worker_count(max_workers))

    def for_items(self, item_count: int) -> int:
        return bounded_worker_count(self.total, item_count)

    def split(
        self, phase_count: int, *, phase_cap: int | None = None
    ) -> tuple[int, int]:
        if phase_count <= 0:
            return 0, self.total
        phase_limit = phase_count
        if phase_cap is not None:
            phase_limit = min(phase_limit, coerce_worker_count(phase_cap))
        phase_workers = max(1, min(self.total, phase_limit))
        per_phase_workers = max(1, self.total // phase_workers)
        return phase_workers, per_phase_workers


def serialized_progress_callback(callback):
    if callback is None:
        return None
    if getattr(callback, "_metis_serialized_progress_callback", False):
        return callback

    lock = threading.Lock()

    def _serialized(event):
        with lock:
            return callback(event)

    _serialized._metis_serialized_progress_callback = True
    return _serialized


def run_reachability_jobs(
    jobs: Iterable[JobT],
    worker: Callable[[JobT], ResultT],
    *,
    max_workers: int | str | None,
    label: str,
    result_key: Callable[[JobT], Any] | None = None,
    on_complete: Callable[[Any, int, int], None] | None = None,
    on_result: Callable[[Any, int, int, ResultT], None] | None = None,
    swallow_exceptions: bool = True,
) -> list[ResultT]:
    job_list = list(jobs)
    if not job_list:
        return []

    total = len(job_list)
    worker_count = bounded_worker_count(max_workers, total)
    results: list[ResultT] = []

    def key_for(job):
        return result_key(job) if result_key else job

    def collect(job, completed, result_func):
        key = key_for(job)
        try:
            result = result_func()
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            if not swallow_exceptions:
                raise
            logger.warning("%s failed for %s: %s", label, key, exc)
        else:
            results.append(result)
            if on_result:
                on_result(key, completed, total, result)
        if on_complete:
            on_complete(key, completed, total)

    if worker_count == 1:
        for completed, job in enumerate(job_list, start=1):
            collect(job, completed, lambda job=job: worker(job))
        return results

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            submit_with_current_context(executor, worker, job): job for job in job_list
        }
        for completed, future in enumerate(as_completed(futures), start=1):
            collect(futures[future], completed, future.result)
    return results
