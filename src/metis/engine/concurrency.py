# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import threading
from collections.abc import Callable
from collections.abc import Sequence
from concurrent.futures import Executor
from concurrent.futures import FIRST_COMPLETED
from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait
from typing import TYPE_CHECKING

from metis import runlog
from metis.usage import submit_with_current_context

if TYPE_CHECKING:
    from metis.engine.execution.contracts import NodeJobs


class JobScheduler:
    def __init__(self, max_workers: int) -> None:
        self._max_workers = max_workers
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="metis",
        )

    def limit(self, max_concurrency: int) -> "NodeJobs":
        return _NodeJobs(
            self._executor,
            self._max_workers,
        ).limit(max_concurrency)

    def close(self) -> None:
        self._executor.shutdown()


class _NodeJobs:
    def __init__(self, executor: Executor, max_concurrency: int) -> None:
        self._executor = executor
        self._max_concurrency = max_concurrency

    def limit(self, max_concurrency: int) -> "_NodeJobs":
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        return _NodeJobs(
            self._executor,
            min(max_concurrency, self._max_concurrency),
        )

    def run[JobT, ResultT](
        self,
        jobs: Sequence[JobT],
        worker: Callable[[JobT], ResultT],
        *,
        label: str | None,
        result_key: Callable[[JobT], object],
        on_complete: Callable[[JobT, int, int], None] | None = None,
    ) -> list[ResultT]:
        if not jobs:
            return []

        total = len(jobs)
        worker_count = min(self._max_concurrency, total)
        results: list[ResultT] = []

        def invoke_worker(job: JobT) -> ResultT:
            if label is None:
                return worker(job)
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

        job_iterator = iter(jobs)
        futures: dict[Future[ResultT], JobT] = {}
        completed = 0
        try:
            for job in job_iterator:
                futures[
                    submit_with_current_context(self._executor, invoke_worker, job)
                ] = job
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
                    futures[
                        submit_with_current_context(self._executor, invoke_worker, job)
                    ] = job
                    if len(futures) >= worker_count:
                        break
        except BaseException:
            for future in futures:
                future.cancel()
            wait(futures)
            raise
        return results


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
