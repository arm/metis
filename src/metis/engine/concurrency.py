# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Callable
from collections.abc import Sequence
from concurrent.futures import CancelledError
from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor
from contextvars import Context
from contextvars import copy_context
from dataclasses import dataclass
from dataclasses import field
from functools import partial
from typing import TYPE_CHECKING
from typing import Any

from metis import runlog

if TYPE_CHECKING:
    from metis.engine.execution.contracts import NodeJobs


@dataclass(eq=False, slots=True)
class _JobRun[JobT, ResultT]:
    pending: deque[JobT]
    worker: Callable[[JobT], ResultT]
    max_concurrency: int
    context: Context
    cancellation: threading.Event | None
    total: int
    active: dict[Future[ResultT], JobT] = field(default_factory=dict)
    completed: deque[tuple[JobT, Future[ResultT]]] = field(default_factory=deque)
    collecting: bool = False
    cancelled: bool = False


class JobScheduler:
    def __init__(self, max_workers: int) -> None:
        self._max_workers = max_workers
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="metis",
        )
        self._condition = threading.Condition()
        self._runs: list[_JobRun[Any, Any]] = []
        self._active_workers = 0
        self._cursor = 0
        self._closed = False

    def limit(self, max_concurrency: int) -> "NodeJobs":
        return _NodeJobs(self, self._max_workers, None).limit(max_concurrency)

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            for run in tuple(self._runs):
                self._cancel_locked(run)
        self._executor.shutdown(cancel_futures=True)

    def run[JobT, ResultT](
        self,
        jobs: Sequence[JobT],
        worker: Callable[[JobT], ResultT],
        *,
        max_concurrency: int,
        cancellation: threading.Event | None,
        label: str | None,
        result_key: Callable[[JobT], object],
        on_complete: Callable[[JobT, int, int], None] | None,
    ) -> list[ResultT]:
        if not jobs:
            return []

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

        run = _JobRun(
            pending=deque(jobs),
            worker=invoke_worker,
            max_concurrency=min(max_concurrency, self._max_workers),
            context=copy_context(),
            cancellation=cancellation,
            total=len(jobs),
        )
        self._register(run)
        results: list[ResultT] = []
        completed_count = 0
        try:
            while completed_count < run.total:
                with self._condition:
                    self._condition.wait_for(
                        lambda: bool(run.completed) or run.cancelled
                    )
                    completed = tuple(run.completed)
                    run.completed.clear()
                    cancelled = run.cancelled
                    run.collecting = bool(completed) and not cancelled
                if cancelled:
                    with self._condition:
                        self._condition.wait_for(lambda: not run.active)
                    raise CancelledError("Concurrent jobs were cancelled")
                for job, future in completed:
                    results.append(future.result())
                    completed_count += 1
                    if on_complete is not None:
                        on_complete(job, completed_count, run.total)
                with self._condition:
                    run.collecting = False
                    self._dispatch_locked()
            return results
        except BaseException:
            with self._condition:
                self._cancel_locked(run)
                self._condition.wait_for(lambda: not run.active)
            raise
        finally:
            self._remove(run)

    def cancel(self, cancellation: threading.Event) -> None:
        cancellation.set()
        with self._condition:
            for run in tuple(self._runs):
                if run.cancellation is cancellation:
                    self._cancel_locked(run)

    def _register(self, run: _JobRun[Any, Any]) -> None:
        with self._condition:
            if self._closed:
                raise RuntimeError("cannot schedule new futures after shutdown")
            if run.cancellation is not None and run.cancellation.is_set():
                raise CancelledError("Concurrent jobs were cancelled")
            self._runs.append(run)
            self._cursor = len(self._runs) - 1
            self._dispatch_locked()

    def _remove(self, run: _JobRun[Any, Any]) -> None:
        with self._condition:
            if run not in self._runs:
                return
            index = self._runs.index(run)
            self._runs.pop(index)
            if self._runs:
                if index < self._cursor:
                    self._cursor -= 1
                self._cursor %= len(self._runs)
            else:
                self._cursor = 0
            self._dispatch_locked()

    def _cancel_locked(self, run: _JobRun[Any, Any]) -> None:
        if run.cancelled:
            return
        run.cancelled = True
        run.pending.clear()
        for future in tuple(run.active):
            future.cancel()
        self._condition.notify_all()

    def _dispatch_locked(self) -> None:
        available = self._max_workers - self._active_workers
        while not self._closed and available > 0:
            run = self._next_run_locked()
            if run is None:
                return
            job = run.pending.popleft()
            future = self._executor.submit(
                run.context.copy().run,
                run.worker,
                job,
            )
            run.active[future] = job
            self._active_workers += 1
            available -= 1
            future.add_done_callback(partial(self._complete, run))

    def _next_run_locked(self) -> _JobRun[Any, Any] | None:
        for run in self._runs:
            if run.cancellation is not None and run.cancellation.is_set():
                self._cancel_locked(run)
        eligible = [
            run
            for run in self._runs
            if not run.cancelled
            and run.pending
            and not run.completed
            and not run.collecting
            and len(run.active) < run.max_concurrency
        ]
        if not eligible:
            return None
        minimum_active = min(len(run.active) for run in eligible)
        for offset in range(len(self._runs)):
            index = (self._cursor + offset) % len(self._runs)
            run = self._runs[index]
            if run in eligible and len(run.active) == minimum_active:
                self._cursor = (index + 1) % len(self._runs)
                return run
        raise AssertionError("Fair job scheduler could not select an eligible run")

    def _complete(
        self,
        run: _JobRun[Any, Any],
        future: Future[Any],
    ) -> None:
        with self._condition:
            job = run.active.pop(future)
            self._active_workers -= 1
            run.completed.append((job, future))
            self._condition.notify_all()


class _NodeJobs:
    def __init__(
        self,
        scheduler: JobScheduler,
        max_concurrency: int,
        cancellation: threading.Event | None,
    ) -> None:
        self._scheduler = scheduler
        self._max_concurrency = max_concurrency
        self._cancellation = cancellation

    def limit(self, max_concurrency: int) -> "_NodeJobs":
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        return _NodeJobs(
            self._scheduler,
            min(max_concurrency, self._max_concurrency),
            self._cancellation,
        )

    def with_cancellation(self, cancellation: threading.Event) -> "_NodeJobs":
        return _NodeJobs(self._scheduler, self._max_concurrency, cancellation)

    def cancel(self) -> None:
        if self._cancellation is not None:
            self._scheduler.cancel(self._cancellation)

    def run[JobT, ResultT](
        self,
        jobs: Sequence[JobT],
        worker: Callable[[JobT], ResultT],
        *,
        label: str | None,
        result_key: Callable[[JobT], object],
        on_complete: Callable[[JobT, int, int], None] | None = None,
    ) -> list[ResultT]:
        return self._scheduler.run(
            jobs,
            worker,
            max_concurrency=self._max_concurrency,
            cancellation=self._cancellation,
            label=label,
            result_key=result_key,
            on_complete=on_complete,
        )


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
