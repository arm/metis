# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import threading
from collections.abc import Callable
from collections.abc import Sequence
from concurrent.futures import FIRST_COMPLETED
from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait
from functools import partial

from metis import runlog
from metis.usage import submit_with_current_context


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


def run_jobs[JobT, ResultT](
    jobs: Sequence[JobT],
    worker: Callable[[JobT], ResultT],
    *,
    max_workers: int | str | None,
    label: str,
    result_key: Callable[[JobT], object],
    on_complete: Callable[[JobT, int, int], None] | None = None,
) -> list[ResultT]:
    if not jobs:
        return []

    total = len(jobs)
    worker_count = bounded_worker_count(max_workers, total)
    results: list[ResultT] = []

    def invoke_worker(job: JobT) -> ResultT:
        key = result_key(job)
        with runlog.span(
            "task",
            label,
            {"kind": "concurrent_job", "key": key},
        ) as task_span:
            runlog.bump("tasks")
            result = worker(job)
            task_span.end(attributes={"result": result})
            return result

    def collect(
        job: JobT,
        completed: int,
        result_func: Callable[[], ResultT],
    ) -> None:
        results.append(result_func())
        if on_complete:
            on_complete(job, completed, total)

    if worker_count == 1:
        for completed, job in enumerate(jobs, start=1):
            collect(job, completed, partial(invoke_worker, job))
        return results

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        job_iterator = iter(jobs)
        futures: dict[Future[ResultT], JobT] = {}
        completed = 0

        for job in job_iterator:
            futures[submit_with_current_context(executor, invoke_worker, job)] = job
            if len(futures) >= worker_count:
                break

        while futures:
            completed_futures, _pending = wait(
                futures,
                return_when=FIRST_COMPLETED,
            )
            for future in completed_futures:
                completed += 1
                collect(futures.pop(future), completed, future.result)
            for job in job_iterator:
                futures[submit_with_current_context(executor, invoke_worker, job)] = job
                if len(futures) >= worker_count:
                    break
    return results
