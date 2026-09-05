# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import CancelledError
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from contextvars import copy_context
from threading import Barrier
from threading import Event
from threading import Lock
from threading import Thread
from threading import get_ident

import pytest

from metis.engine.concurrency import JobScheduler
from metis.engine.concurrency import serialized_progress_callback
from metis.execution_nodes import NodeRuntime


WAIT = 2


@pytest.fixture
def scheduler():
    scheduler = JobScheduler(2)
    try:
        yield scheduler
    finally:
        scheduler.close()


@pytest.fixture
def start_run(scheduler, monkeypatch):
    registered = Event()
    original = scheduler._register

    def register(run):
        try:
            return original(run)
        finally:
            registered.set()

    # Observe admission only, so tests release workers after competing runs are queued.
    monkeypatch.setattr(scheduler, "_register", register)
    with ThreadPoolExecutor(max_workers=3) as callers:

        def start(jobs, values, worker, **kwargs):
            registered.clear()
            future = callers.submit(
                jobs.run, values, worker, label=None, result_key=str, **kwargs
            )
            assert registered.wait(WAIT), "job caller never registered its run"
            return future

        yield start


def test_jobs_preserve_context_and_none_values_off_the_caller(scheduler):
    value = ContextVar("test_job_value", default="unset")
    caller = get_ident()
    token = value.set("caller")

    def worker(job):
        assert get_ident() != caller
        assert value.get() == "caller"
        value.set("worker")
        return job

    try:
        assert scheduler.limit(1).run(
            [None, 2], worker, label=None, result_key=str
        ) == [None, 2]
        assert value.get() == "caller"
    finally:
        value.reset(token)


def test_results_and_callbacks_follow_completion_order(scheduler):
    first_started = Event()
    release_first = Event()
    completed = []

    def worker(value):
        if value == 1:
            first_started.set()
            assert release_first.wait(WAIT)
        else:
            assert first_started.wait(WAIT)
        return value

    def collect(value, count, total):
        completed.append((value, count, total))
        if value == 2:
            release_first.set()

    try:
        assert scheduler.limit(2).run(
            [1, 2], worker, label=None, result_key=str, on_complete=collect
        ) == [2, 1]
    finally:
        release_first.set()
    assert completed == [(2, 1, 2), (1, 2, 2)]


@pytest.mark.parametrize("operation", ["run", "close"])
def test_finished_worker_context_does_not_remain_a_worker(scheduler, operation):
    jobs = scheduler.limit(1)
    copied = jobs.run([1], lambda _: copy_context(), label=None, result_key=str)[0]
    if operation == "close":
        copied.run(scheduler.close)
    else:
        assert copied.run(
            jobs.run, [2], lambda value: value, label=None, result_key=str
        ) == [2]


@pytest.mark.parametrize("operation", ["run", "close"])
def test_worker_cannot_reenter_or_close_its_own_scheduler(operation):
    scheduler = JobScheduler(1)
    jobs = scheduler.limit(1).with_cancellation(Event())

    def worker(value):
        with pytest.raises(RuntimeError):
            if operation == "close":
                scheduler.close()
            else:
                jobs.run([value], lambda job: job, label=None, result_key=str)
        return value

    with ThreadPoolExecutor(max_workers=1) as caller:
        result = caller.submit(jobs.run, [1], worker, label=None, result_key=str)
        try:
            assert result.result(WAIT) == [1]
            assert jobs.run([2], lambda value: value, label=None, result_key=str) == [2]
        finally:
            jobs.cancel()
            scheduler.close()


@pytest.mark.parametrize("view_limit", [None, 1, 2])
def test_concurrent_limit_views_share_capacity_and_leave_other_nodes_room(
    scheduler, start_run, view_limit
):
    jobs = scheduler.limit(1)
    release = Event()
    first_started = Event()
    lock = Lock()
    active = peak = 0

    def worker(value):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        first_started.set()
        try:
            assert release.wait(WAIT)
            return value
        finally:
            with lock:
                active -= 1

    first = start_run(jobs, [1], worker)
    assert first_started.wait(WAIT)
    view = jobs if view_limit is None else jobs.limit(view_limit)
    second = start_run(view, [2], worker)
    try:
        # A quota violation occupies both workers and prevents this probe from finishing.
        probe = start_run(scheduler.limit(1), [3], lambda value: value)
        assert probe.result(WAIT) == [3]
    finally:
        release.set()
    assert first.result(WAIT) == [1]
    assert second.result(WAIT) == [2]
    assert peak == 1


def test_slow_collector_blocks_its_own_queue_but_not_another_run(scheduler, start_run):
    jobs = scheduler.limit(1)
    release_worker = Event()
    collecting = Event()
    release_collector = Event()
    later_started = Event()

    def worker(value):
        if value == 1:
            assert release_worker.wait(WAIT)
        else:
            later_started.set()
        return value

    def collect(value, _count, _total):
        if value == 1:
            collecting.set()
            assert release_collector.wait(WAIT)

    # Fill the second global slot so the other run is already queued when work completes.
    occupied = Event()
    release_occupied = Event()

    def occupy(value):
        occupied.set()
        assert release_occupied.wait(WAIT)
        return value

    holder = start_run(scheduler.limit(1), [0], occupy)
    assert occupied.wait(WAIT)
    first = start_run(jobs, [1, 2], worker, on_complete=collect)
    other = start_run(scheduler.limit(1), [3], lambda value: value)
    try:
        release_worker.set()
        assert collecting.wait(WAIT)
        assert other.result(WAIT) == [3]
        assert not later_started.is_set()
    finally:
        release_collector.set()
        release_occupied.set()
        release_worker.set()
    assert first.result(WAIT) == [1, 2]
    assert holder.result(WAIT) == [0]


@pytest.mark.parametrize("action", ["cancel", "parent", "close"])
def test_cancellation_signals_active_jobs_and_discards_queued_work(
    scheduler, monkeypatch, action
):
    parent = Event()
    cancellation = Event()
    jobs = scheduler.limit(2).with_cancellation(parent).with_cancellation(cancellation)
    started = Barrier(3)
    observed = []
    release = Event()
    draining = Event()
    wait_for = scheduler._condition.wait_for

    def observe_drain(predicate, timeout=None):
        if cancellation.is_set() and timeout is None and not predicate():
            draining.set()
        return wait_for(predicate, timeout)

    monkeypatch.setattr(scheduler._condition, "wait_for", observe_drain)

    def worker(value):
        started.wait(WAIT)
        observed.append((value, cancellation.wait(WAIT)))
        if action != "close":
            assert release.wait(WAIT)
        return value

    with ThreadPoolExecutor(max_workers=1) as caller:
        result = caller.submit(jobs.run, [0, 1, 2], worker, label=None, result_key=str)
        try:
            started.wait(WAIT)
            if action == "close":
                scheduler.close()
            elif action == "parent":
                parent.set()
            else:
                jobs.cancel()
            if action != "close":
                assert draining.wait(WAIT), "cancelled run must block while draining"
                assert not result.done()
                release.set()
            with pytest.raises(CancelledError):
                result.result(WAIT)
        finally:
            release.set()
            cancellation.set()
            jobs.cancel()
    assert sorted(observed) == [(0, True), (1, True)]
    assert parent.is_set() is (action == "parent")


def test_job_error_signals_its_explicit_scope_without_cancelling_parent(scheduler):
    parent = Event()
    cancellation = Event()
    jobs = scheduler.limit(2).with_cancellation(parent).with_cancellation(cancellation)
    peer_started = Event()
    observed = []

    def worker(value):
        if value == 0:
            assert peer_started.wait(WAIT)
            raise RuntimeError("worker failed")
        peer_started.set()
        observed.append(cancellation.wait(WAIT))
        return value

    with pytest.raises(RuntimeError, match="worker failed"):
        jobs.run([0, 1], worker, label=None, result_key=str)
    assert observed == [True]
    assert not parent.is_set()
    with pytest.raises(CancelledError):
        jobs.run([], worker, label=None, result_key=str)
    assert scheduler.limit(1).run(
        [2], lambda value: value, label=None, result_key=str
    ) == [2]


@pytest.mark.parametrize("failure", ["worker", "callback", "submission"])
def test_failed_plain_run_is_cleaned_up_and_handle_can_be_reused(
    scheduler, monkeypatch, failure
):
    jobs = scheduler.limit(1)
    observed = []

    def fail(*_args, **_kwargs):
        raise RuntimeError("expected failure")

    def worker(value):
        observed.append(value)
        if failure == "worker" and value == 1:
            fail()
        return value

    with monkeypatch.context() as patch:
        if failure == "submission":
            patch.setattr(scheduler._executor, "submit", fail)
        with pytest.raises(RuntimeError, match="expected failure"):
            jobs.run(
                [1, 2],
                worker,
                label=None,
                result_key=str,
                on_complete=fail if failure == "callback" else None,
            )
    assert jobs.run([3], worker, label=None, result_key=str) == [3]
    scheduler.close()
    assert observed == ([3] if failure == "submission" else [1, 3])


def test_completion_callback_can_submit_and_cancel_its_final_result(scheduler):
    jobs = scheduler.limit(1)
    nested = []

    def complete(value, _count, _total):
        nested.extend(
            jobs.run([value + 1], lambda job: job, label=None, result_key=str)
        )
        jobs.cancel()

    with pytest.raises(CancelledError):
        jobs.run(
            [1], lambda value: value, label=None, result_key=str, on_complete=complete
        )
    assert nested == [2]


def test_closed_scheduler_rejects_empty_and_nonempty_work(scheduler):
    jobs = scheduler.limit(1)
    scheduler.close()
    scheduler.close()
    for values in ([], [1]):
        with pytest.raises(RuntimeError, match="shutdown"):
            jobs.run(values, lambda value: value, label=None, result_key=str)


def test_serialized_progress_callback_allows_same_thread_reentry():
    observed = []

    def callback(event):
        observed.append(event)
        if event == 0:
            wrapped(1)

    wrapped = serialized_progress_callback(callback)
    assert serialized_progress_callback(wrapped) is wrapped
    thread = Thread(target=wrapped, args=(0,), daemon=True)
    thread.start()
    thread.join(WAIT)
    assert not thread.is_alive(), "same-thread progress reentry deadlocked"
    assert observed == [0, 1]


@pytest.mark.parametrize("maximum", [0, -1, True, 1.5, "2"])
@pytest.mark.parametrize("entry", ["scheduler", "handle", "run"])
def test_worker_limits_require_positive_integers(scheduler, maximum, entry):
    with pytest.raises(ValueError):
        if entry == "scheduler":
            JobScheduler(maximum)
        elif entry == "handle":
            scheduler.limit(maximum)
        else:
            scheduler.run(
                [],
                lambda value: value,
                max_concurrency=maximum,
                cancellation=None,
                label=None,
                result_key=str,
                on_complete=None,
            )


@pytest.mark.parametrize("cancel_parent", [False, True])
def test_runtime_child_scopes_share_job_cancellation_without_cancelling_siblings(
    scheduler, cancel_parent
):
    root = Event()
    runtime = NodeRuntime(
        model="unused",
        max_workers=2,
        max_token_length=1,
        chat_model_kwargs={},
        jobs=scheduler.limit(2).with_cancellation(root),
        is_cancelled=root.is_set,
    )
    child = runtime._with_cancellation()
    sibling = runtime._with_cancellation()
    grandchild = child._with_cancellation()
    if cancel_parent:
        root.set()
    else:
        child.jobs.cancel()
    assert child.is_cancelled()
    assert grandchild.is_cancelled()
    assert runtime.is_cancelled() is cancel_parent
    assert sibling.is_cancelled() is cancel_parent
    for cancelled in (child, grandchild):
        with pytest.raises(CancelledError):
            cancelled.jobs.run([1], lambda value: value, label=None, result_key=str)
    if not cancel_parent:
        assert sibling.jobs.run(
            [2], lambda value: value, label=None, result_key=str
        ) == [2]
        assert runtime.jobs.run(
            [3], lambda value: value, label=None, result_key=str
        ) == [3]


def test_runtime_cancellation_scope_requires_a_job_handle():
    runtime = NodeRuntime(
        model="unused", max_workers=1, max_token_length=1, chat_model_kwargs={}
    )
    with pytest.raises(RuntimeError, match="scheduler is unavailable"):
        runtime._with_cancellation()


def test_repeated_interruptions_drain_workers_before_preserving_original_error(
    scheduler, monkeypatch
):
    started = Event()
    release = Event()
    draining = Event()
    wait_for = scheduler._condition.wait_for
    waits = 0

    def interrupted_wait(predicate, timeout=None):
        nonlocal waits
        waits += 1
        if waits == 1:
            assert wait_for(started.is_set, WAIT)
            raise KeyboardInterrupt("initial interruption")
        if waits == 2:
            raise KeyboardInterrupt("cleanup interruption")
        draining.set()
        return wait_for(predicate, timeout)

    def worker(value):
        started.set()
        assert release.wait(WAIT * 2)
        return value

    monkeypatch.setattr(scheduler._condition, "wait_for", interrupted_wait)
    with ThreadPoolExecutor(max_workers=1) as caller:
        result = caller.submit(
            scheduler.limit(1).run, [1], worker, label=None, result_key=str
        )
        try:
            assert draining.wait(WAIT), "cleanup abandoned its active worker"
            assert not result.done()
            release.set()
            with pytest.raises(KeyboardInterrupt, match="initial interruption"):
                result.result(WAIT)
        finally:
            release.set()
    assert scheduler.limit(1).run(
        [2], lambda value: value, label=None, result_key=str
    ) == [2]
