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
from contextlib import suppress
from contextvars import Context
from contextvars import ContextVar
from contextvars import copy_context
from dataclasses import dataclass
from dataclasses import field
from functools import partial
from typing import TYPE_CHECKING
from typing import Any

from metis import runlog

if TYPE_CHECKING:
    from metis.engine.execution.contracts import NodeJobs


def _validate_worker_limit(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")


@dataclass(eq=False, slots=True)
class _JobQuota:
    limit: int
    active: int = 0


@dataclass(eq=False, slots=True)
class _JobRun[JobT, ResultT]:
    pending: deque[JobT]
    worker: Callable[[JobT], ResultT]
    max_concurrency: int
    context: Context
    cancellation: threading.Event | None
    parents: tuple[threading.Event, ...]
    quotas: tuple[_JobQuota, ...]
    total: int
    active: dict[Future[ResultT], JobT] = field(default_factory=dict)
    completed: deque[tuple[JobT, Future[ResultT]]] = field(default_factory=deque)
    collecting: bool = False
    cancelled: bool = False
    failure: BaseException | None = None


class JobScheduler:
    def __init__(self, max_workers: int) -> None:
        _validate_worker_limit(max_workers, "max_workers")
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
        self._dispatching = False
        self._in_worker: ContextVar[threading.Event | None] = ContextVar(
            "metis_scheduler_worker", default=None
        )

    def limit(self, max_concurrency: int) -> "NodeJobs":
        return _NodeJobs(self, self._max_workers, threading.Event()).limit(
            max_concurrency
        )

    def close(self) -> None:
        active_worker = self._in_worker.get()
        if active_worker is not None and active_worker.is_set():
            raise RuntimeError("Cannot close a job scheduler from its own worker")
        with self._condition:
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
        parents: tuple[threading.Event, ...] = (),
        quotas: tuple[_JobQuota, ...] = (),
    ) -> list[ResultT]:
        _validate_worker_limit(max_concurrency, "max_concurrency")
        active_worker = self._in_worker.get()
        if active_worker is not None and active_worker.is_set():
            raise RuntimeError("Nested jobs on the same scheduler are not supported")
        with self._condition:
            if self._closed:
                raise RuntimeError("cannot schedule new futures after shutdown")
            if (cancellation is not None and cancellation.is_set()) or any(
                parent.is_set() for parent in parents
            ):
                raise CancelledError("Concurrent jobs were cancelled")
        if not jobs:
            return []

        def invoke_worker(job: JobT) -> ResultT:
            active_worker = threading.Event()
            active_worker.set()
            token = self._in_worker.set(active_worker)
            try:
                if run.cancelled:
                    raise CancelledError("Concurrent jobs were cancelled")
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
            finally:
                active_worker.clear()
                self._in_worker.reset(token)

        run = _JobRun(
            pending=deque(jobs),
            worker=invoke_worker,
            max_concurrency=min(max_concurrency, self._max_workers),
            context=copy_context(),
            cancellation=cancellation,
            parents=parents,
            quotas=quotas,
            total=len(jobs),
        )
        results: list[ResultT] = []
        completed_count = 0
        try:
            self._register(run)
            while completed_count < run.total:
                with self._condition:
                    self._condition.wait_for(
                        lambda: bool(run.completed) or run.cancelled,
                        timeout=0.1 if cancellation is not None or parents else None,
                    )
                    if self._is_cancelled(run):
                        self._cancel_locked(run)
                    completed = tuple(run.completed)
                    run.completed.clear()
                    cancelled = run.cancelled
                    run.collecting = bool(completed) and not cancelled
                if cancelled:
                    with self._condition:
                        self._condition.wait_for(lambda: not run.active)
                    if run.failure is not None:
                        raise run.failure
                    raise CancelledError("Concurrent jobs were cancelled")
                for job, future in completed:
                    results.append(future.result())
                    completed_count += 1
                    if on_complete is not None:
                        on_complete(job, completed_count, run.total)
                    if run.cancelled or self._is_cancelled(run):
                        raise CancelledError("Concurrent jobs were cancelled")
                with self._condition:
                    run.collecting = False
                    self._dispatch_locked()
            return results
        except BaseException:
            with self._condition:
                self._cancel_locked(run)
                while run.active:
                    with suppress(BaseException):
                        self._condition.wait_for(lambda: not run.active)
            raise
        finally:
            self._remove(run)

    def cancel(self, cancellation: threading.Event) -> None:
        cancellation.set()
        with self._condition:
            for run in tuple(self._runs):
                if run.cancellation is cancellation or cancellation in run.parents:
                    self._cancel_locked(run)

    def _register(self, run: _JobRun[Any, Any]) -> None:
        with self._condition:
            if self._closed:
                raise RuntimeError("cannot schedule new futures after shutdown")
            if self._is_cancelled(run):
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
        if run.cancellation is not None:
            run.cancellation.set()
        run.pending.clear()
        for future in tuple(run.active):
            future.cancel()
        self._condition.notify_all()

    @staticmethod
    def _is_cancelled(run: _JobRun[Any, Any]) -> bool:
        return (run.cancellation is not None and run.cancellation.is_set()) or any(
            parent.is_set() for parent in run.parents
        )

    def _dispatch_locked(self) -> None:
        if self._dispatching:
            return
        self._dispatching = True
        try:
            while not self._closed and self._active_workers < self._max_workers:
                run = self._next_run_locked()
                if run is None:
                    return
                job = run.pending.popleft()
                try:
                    future = self._executor.submit(
                        run.context.copy().run,
                        run.worker,
                        job,
                    )
                except BaseException as error:
                    run.failure = error
                    self._cancel_locked(run)
                    continue
                run.active[future] = job
                self._active_workers += 1
                for quota in run.quotas:
                    quota.active += 1
                future.add_done_callback(partial(self._complete, run))
        finally:
            self._dispatching = False

    def _next_run_locked(self) -> _JobRun[Any, Any] | None:
        for run in self._runs:
            if self._is_cancelled(run):
                self._cancel_locked(run)
        # Prefer less active runs, breaking ties from the rotating cursor.
        index = min(
            (
                index
                for index, run in enumerate(self._runs)
                if not run.cancelled
                and run.pending
                and not run.completed
                and not run.collecting
                and len(run.active) < run.max_concurrency
                and all(quota.active < quota.limit for quota in run.quotas)
            ),
            key=lambda index: (
                len(self._runs[index].active),
                (index - self._cursor) % len(self._runs),
            ),
            default=None,
        )
        if index is None:
            return None
        self._cursor = (index + 1) % len(self._runs)
        return self._runs[index]

    def _complete(
        self,
        run: _JobRun[Any, Any],
        future: Future[Any],
    ) -> None:
        with self._condition:
            job = run.active.pop(future)
            self._active_workers -= 1
            for quota in run.quotas:
                quota.active -= 1
            run.completed.append((job, future))
            self._dispatch_locked()
            self._condition.notify_all()


class _NodeJobs:
    def __init__(
        self,
        scheduler: JobScheduler,
        max_concurrency: int,
        cancellation: threading.Event | None,
        parents: tuple[threading.Event, ...] = (),
        quotas: tuple[_JobQuota, ...] = (),
        explicit_cancellation: bool = False,
    ) -> None:
        self._scheduler = scheduler
        self._max_concurrency = max_concurrency
        self._cancellation = cancellation
        self._parents = parents
        self._quotas = quotas
        self._explicit_cancellation = explicit_cancellation

    def limit(self, max_concurrency: int) -> "_NodeJobs":
        _validate_worker_limit(max_concurrency, "max_concurrency")
        maximum = min(max_concurrency, self._max_concurrency)
        quotas = self._quotas
        if not quotas or maximum < self._max_concurrency:
            quotas = (*quotas, _JobQuota(maximum))
        return _NodeJobs(
            self._scheduler,
            maximum,
            self._cancellation,
            self._parents,
            quotas,
            self._explicit_cancellation,
        )

    def with_cancellation(self, cancellation: threading.Event) -> "_NodeJobs":
        """Inherit parent cancellation; cancelling this scope leaves parents intact."""
        parents = self._parents
        if self._cancellation is not None and self._cancellation is not cancellation:
            parents = (*parents, self._cancellation)
        return _NodeJobs(
            self._scheduler,
            self._max_concurrency,
            cancellation,
            parents,
            self._quotas,
            True,
        )

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
        cancellation = self._cancellation
        parents = self._parents
        if not self._explicit_cancellation:
            if cancellation is not None:
                parents = (*parents, cancellation)
            cancellation = threading.Event()
        return self._scheduler.run(
            jobs,
            worker,
            max_concurrency=self._max_concurrency,
            cancellation=cancellation,
            label=label,
            result_key=result_key,
            on_complete=on_complete,
            parents=parents,
            quotas=self._quotas,
        )


def serialized_progress_callback(callback):
    if callback is None:
        return None
    if getattr(callback, "_metis_serialized_progress_callback", False):
        return callback

    lock = threading.RLock()

    def _serialized(event):
        with lock:
            return callback(event)

    _serialized._metis_serialized_progress_callback = True
    return _serialized
