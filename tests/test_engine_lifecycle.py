# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
import sys
from concurrent.futures import CancelledError
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest.mock import Mock

import pytest

from metis.engine import MetisEngine
from metis.engine import core
from metis.engine.capabilities.contracts import CapabilityRegistration
from metis.engine.capabilities.manifest import CapabilityManifest
from metis.engine.execution.contracts import EmptyNodeConfiguration


def _run_in_subprocess(request):
    node = f"{Path(__file__).resolve()}::{request.node.name}"
    if os.environ.get("METIS_LIFECYCLE_TEST") == node:
        return False
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-o", "faulthandler_timeout=10", node],
        env={**os.environ, "METIS_LIFECYCLE_TEST": node},
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return True


class _ObservedLock:
    def __init__(self, lock):
        self._lock = lock
        self.contended = Event()

    def __enter__(self):
        if not self._lock.acquire(blocking=False):
            self.contended.set()
            self._lock.acquire()
        return self

    def __exit__(self, *_args):
        self._lock.release()


class _LocalBackend:
    """An inert storage boundary; readers, splitters and engine execution stay real."""

    def __init__(self):
        self.embed_model_code = object()
        self.embed_model_docs = object()
        self.documents = ["previous index"]
        self.writes = []
        self.write_kwargs = []
        self.reset_count = 0
        self.close_count = 0
        self.closed = Event()
        self.write_started = Event()
        self.finish_write = Event()
        self.finish_write.set()
        self.fail_next_write = False
        self.on_write = None
        self.close_error = None

    def init(self):
        if self.closed.is_set():
            raise RuntimeError("backend was closed during indexing")

    def reset_index(self):
        self.init()
        self.reset_count += 1
        self.documents = []

    def index_nodes(self, code, docs, **kwargs):
        self.write_started.set()
        assert self.finish_write.wait(5)
        self.init()
        if self.on_write is not None:
            self.on_write()
        if self.fail_next_write:
            self.fail_next_write = False
            raise ValueError("storage temporarily unavailable")
        self.documents = [node.text for node in [*code, *docs]]
        self.writes.append(tuple(self.documents))
        self.write_kwargs.append(kwargs)

    def get_retrievers(self, *args, **kwargs):
        self.init()
        return "code retriever", "docs retriever"

    def get_index_handles(self, **kwargs):
        self.init()
        return None, None

    def close(self):
        self.close_count += 1
        self.closed.set()
        if self.close_error is not None:
            raise self.close_error


def _engine(tmp_path, capability_settings, backend, **kwargs):
    return MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=backend,
        max_workers=kwargs.pop("max_workers", 2),
        max_token_length=2048,
        llama_query_model="unused",
        similarity_top_k=3,
        capability_settings=capability_settings,
        execution_config=kwargs.pop(
            "execution_config",
            {
                "stages": {
                    "initialize": {
                        "nodes": {"index": {"capabilities": ["index"]}},
                        "outputs": {"index": "index.index"},
                    }
                }
            },
        ),
        **kwargs,
    )


def test_real_index_preparations_preserve_each_snapshot_until_finalization(
    tmp_path, capability_settings
):
    document = tmp_path / "README.md"
    document.write_text("snapshot A")
    backend = _LocalBackend()
    engine = _engine(tmp_path, capability_settings, backend)
    first_prepared, second_prepared, first_finished = (Event() for _ in range(3))

    def first():
        engine.indexing.index_prepare_nodes()
        first_prepared.set()
        assert second_prepared.wait(5)
        assert backend.documents == ["previous index"]
        engine.indexing.index_finalize_embeddings()
        first_finished.set()

    def second():
        assert first_prepared.wait(5)
        document.write_text("snapshot B")
        engine.indexing.index_prepare_nodes()
        second_prepared.set()
        assert first_finished.wait(5)
        engine.indexing.index_finalize_embeddings()

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = pool.submit(first), pool.submit(second)
            a.result(timeout=10)
            b.result(timeout=10)
        assert backend.writes == [("snapshot A",), ("snapshot B",)]
        assert backend.reset_count == 2
        assert all(
            kwargs["callback_manager"]
            is engine._config.usage_runtime.hooks.callback_manager
            and kwargs["embed_model_code"] is backend.embed_model_code
            and kwargs["embed_model_docs"] is backend.embed_model_docs
            for kwargs in backend.write_kwargs
        )
        assert engine.init_codebase() == {"index": {"status": "indexed"}}
        assert backend.documents == ["snapshot B"]
    finally:
        engine.close()


def test_failed_real_index_can_be_retried_on_the_same_worker(
    tmp_path, capability_settings
):
    document = tmp_path / "README.md"
    document.write_text("first attempt")
    backend = _LocalBackend()
    backend.fail_next_write = True
    engine = _engine(tmp_path, capability_settings, backend)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(ValueError, match="temporarily unavailable"):
                pool.submit(engine.indexing.index_codebase).result(timeout=5)
            document.write_text("successful retry")
            pool.submit(engine.indexing.index_codebase).result(timeout=5)
        assert backend.documents == ["successful retry"]
        assert backend.writes == [("successful retry",)]
    finally:
        engine.close()


def test_engine_shutdown_waits_for_direct_indexing_and_rejects_later_writes(
    tmp_path, capability_settings
):
    (tmp_path / "README.md").write_text("retained output")
    backend = _LocalBackend()
    backend.finish_write.clear()
    engine = _engine(tmp_path, capability_settings, backend)
    index = engine.capabilities["index"]
    assert index.get_retrievers() == ("code retriever", "docs retriever")
    indexing = engine.indexing
    close_started = Event()

    def close():
        close_started.set()
        engine.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        writing = pool.submit(indexing.index_codebase)
        try:
            assert backend.write_started.wait(5)
            closing = pool.submit(close)
            assert close_started.wait(5)
            assert not backend.closed.wait(0.1)
        finally:
            backend.finish_write.set()
        writing.result(timeout=5)
        closing.result(timeout=5)
    engine.close()
    assert backend.documents == ["retained output"]
    assert backend.close_count == 1
    assert engine._state.retriever_code is None
    assert engine._state.retriever_docs is None
    with pytest.raises(RuntimeError, match="closed"):
        indexing.index_codebase()
    assert backend.reset_count == 1


def test_index_shutdown_from_its_own_backend_fails_without_deadlock_or_leak(
    tmp_path, capability_settings, request
):
    if _run_in_subprocess(request):
        return
    (tmp_path / "README.md").write_text("index contents")
    backend = _LocalBackend()
    engine = _engine(tmp_path, capability_settings, backend)
    backend.on_write = engine.close
    with pytest.raises(RuntimeError, match="active index"):
        engine.indexing.index_codebase()
    assert backend.close_count == 1
    engine.close()
    assert backend.close_count == 1


def _add_capability(monkeypatch, registration):
    builtins = core.builtin_capability_registrations
    monkeypatch.setattr(
        core,
        "builtin_capability_registrations",
        lambda *args: (*builtins(*args), registration),
    )


@pytest.mark.parametrize("resource_kind", ("index", "factory"))
def test_concurrent_engine_shutdown_allows_resource_callback_to_close_owner(
    tmp_path, capability_settings, monkeypatch, request, resource_kind
):
    if _run_in_subprocess(request):
        return
    (tmp_path / "README.md").write_text("index contents")
    backend = _LocalBackend()
    entered, release = Event(), Event()
    resource, closed = object(), []

    def factory(_context, _configuration):
        entered.set()
        assert release.wait(5)
        engine.close()
        return resource

    if resource_kind == "factory":
        _add_capability(
            monkeypatch,
            CapabilityRegistration(
                CapabilityManifest("closing"),
                EmptyNodeConfiguration,
                factory,
                closed.append,
            ),
        )
    engine = _engine(tmp_path, capability_settings, backend)
    if resource_kind == "index":
        backend.finish_write = release
        backend.on_write = engine.close
        entered = backend.write_started
        owner, lock_name = engine.indexing, "_mutation_lock"
        operation = engine.indexing.index_codebase
    else:
        owner, lock_name = engine.capabilities, "_lock"

        def operation():
            return engine.capabilities.require("closing")

    observed = _ObservedLock(getattr(owner, lock_name))
    monkeypatch.setattr(owner, lock_name, observed)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            running = pool.submit(operation)
            try:
                assert entered.wait(5)
                closing = pool.submit(engine.close)
                assert observed.contended.wait(5)
            finally:
                release.set()
            result = running.result(timeout=5)
            closing.result(timeout=5)
        if resource_kind == "factory":
            assert result is resource
            assert closed == [resource]
        else:
            assert backend.documents == ["index contents"]
    finally:
        engine.close()
    assert backend.close_count == 1
    with pytest.raises(RuntimeError, match="closed"):
        engine.capabilities.require("index")


@pytest.mark.parametrize("cleanup_fails", (False, True))
def test_engine_never_publishes_a_capability_returned_after_owner_shutdown(
    tmp_path, capability_settings, monkeypatch, cleanup_fails
):
    backend = _LocalBackend()
    closed = []
    resource = object()
    engine = None

    def factory(_context, _configuration):
        assert engine is not None
        engine.close()
        return resource

    def close(resource):
        closed.append(resource)
        if cleanup_fails:
            raise ValueError("resource cleanup failed")

    _add_capability(
        monkeypatch,
        CapabilityRegistration(
            CapabilityManifest("late"), EmptyNodeConfiguration, factory, close
        ),
    )
    engine = _engine(tmp_path, capability_settings, backend)
    with pytest.raises(RuntimeError, match="closed") as caught:
        engine.capabilities.require("late")
    if cleanup_fails:
        assert any("resource cleanup failed" in note for note in caught.value.__notes__)
    assert closed == [resource]
    assert backend.close_count == 1
    with pytest.raises(RuntimeError, match="closed"):
        engine.capabilities.require("late")
    engine.close()
    assert closed == [resource]


def test_real_engine_cleanup_preserves_construction_error_and_closes_owned_index(
    tmp_path, capability_settings
):
    backend = _LocalBackend()
    backend.close_error = RuntimeError("storage close failed")
    with pytest.raises(ValueError, match="no_such_port") as caught:
        _engine(
            tmp_path,
            capability_settings,
            backend,
            execution_config={
                "stages": {
                    "initialize": {
                        "nodes": {"index": {"capabilities": ["index"]}},
                        "outputs": {"index": "index.no_such_port"},
                    }
                }
            },
        )
    assert backend.close_count == 1
    assert any("storage close failed" in note for note in caught.value.__notes__)


def test_real_engine_constructs_a_lazy_capability_once_under_contention(
    tmp_path, capability_settings, monkeypatch, request
):
    if _run_in_subprocess(request):
        return
    entered, release = Event(), Event()
    instances, closed = [], []

    def factory(_context, _configuration):
        instance = object()
        instances.append(instance)
        entered.set()
        assert release.wait(5)
        return instance

    _add_capability(
        monkeypatch,
        CapabilityRegistration(
            CapabilityManifest("shared"), EmptyNodeConfiguration, factory, closed.append
        ),
    )
    engine = _engine(tmp_path, capability_settings, _LocalBackend())

    observed = _ObservedLock(engine.capabilities._lock)
    monkeypatch.setattr(engine.capabilities, "_lock", observed)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(engine.capabilities.require, "shared")
            try:
                assert entered.wait(5)
                other = pool.submit(engine.capabilities.require, "shared")
                assert observed.contended.wait(5)
            finally:
                release.set()
            assert first.result(timeout=5) is other.result(timeout=5)
        assert len(instances) == 1
    finally:
        engine.close()
    engine.close()
    assert closed == instances
    with pytest.raises(RuntimeError, match="closed"):
        engine.capabilities.require("shared")


def test_null_capability_factory_does_not_poison_a_real_engine(
    tmp_path, capability_settings, monkeypatch
):
    (tmp_path / "README.md").write_text("still usable")
    _add_capability(
        monkeypatch,
        CapabilityRegistration(
            CapabilityManifest("invalid"), EmptyNodeConfiguration, lambda *_args: None
        ),
    )
    backend = _LocalBackend()
    engine = _engine(tmp_path, capability_settings, backend)
    try:
        with pytest.raises(TypeError, match="invalid.*None"):
            engine.capabilities.require("invalid")
        assert engine.init_codebase() == {"index": {"status": "indexed"}}
        assert backend.documents == ["still usable"]
    finally:
        engine.close()


def test_reentrant_capability_construction_rejects_same_name_and_allows_retry(
    tmp_path, capability_settings, monkeypatch
):
    resource, dependency, closed = object(), object(), []
    attempts = 0

    def factory(_context, _configuration):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return engine.capabilities.require("recursive")
        assert engine.capabilities.require("dependency") is dependency
        return resource

    for name, build in (
        ("recursive", factory),
        ("dependency", lambda *_args: dependency),
    ):
        _add_capability(
            monkeypatch,
            CapabilityRegistration(
                CapabilityManifest(name), EmptyNodeConfiguration, build, closed.append
            ),
        )
    engine = _engine(tmp_path, capability_settings, _LocalBackend())
    try:
        with pytest.raises(RuntimeError, match="recursive.*already being constructed"):
            engine.capabilities.require("recursive")
        assert attempts == 1
        assert closed == []
        assert engine.capabilities.require("recursive") is resource
        assert engine.capabilities.require("recursive") is resource
        assert attempts == 2
    finally:
        engine.close()
    engine.close()
    assert closed == [resource, dependency]


@pytest.mark.parametrize(
    "name", ["max_workers", "max_active_nodes", "max_concurrent_executions"]
)
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "2"])
def test_direct_engine_rejects_invalid_concurrency_budgets_before_resources(
    tmp_path, capability_settings, name, value
):
    backend = _LocalBackend()
    with pytest.raises(
        ValueError, match=f"MetisEngine.{name} must be a positive integer"
    ):
        _engine(tmp_path, capability_settings, backend, **{name: value})
    assert backend.close_count == 0
    assert backend.writes == []


def test_simultaneous_engine_closers_all_wait_for_active_execution(
    tmp_path, capability_settings, request
):
    if _run_in_subprocess(request):
        return
    entered, release, second_started, second_returned = (Event() for _ in range(4))
    backend = _LocalBackend()
    engine = _engine(tmp_path, capability_settings, backend)
    cancellation = None

    def progress(event):
        nonlocal cancellation
        if event.get("event") == "execution_stage_start":
            (cancellation,) = engine.execution._active_executions
            entered.set()
            assert release.wait(5)

    def close_again():
        second_started.set()
        engine.close()
        second_returned.set()

    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            executing = pool.submit(
                engine.execute_graph, callbacks={"progress_callback": progress}
            )
            try:
                assert entered.wait(5)
                first = pool.submit(engine.close)
                assert cancellation is not None and cancellation.wait(5)
                second = pool.submit(close_again)
                assert second_started.wait(5)
                assert not second_returned.wait(0.1)
                assert not first.done()
                assert not backend.closed.is_set()
            finally:
                release.set()
            with pytest.raises(CancelledError):
                executing.result(timeout=5)
            first.result(timeout=5)
            second.result(timeout=5)
    finally:
        release.set()
        engine.close()
    assert backend.close_count == 1
    assert backend.writes == []


@pytest.mark.parametrize("already_closed", (False, True))
def test_each_engine_closer_preserves_its_shutdown_error(
    tmp_path, capability_settings, monkeypatch, already_closed
):
    backend = _LocalBackend()
    engine = _engine(tmp_path, capability_settings, backend)
    if already_closed:
        engine.close()
    interruption = KeyboardInterrupt("interrupted shutdown")
    scheduler = engine.execution._scheduler
    original_close = scheduler.close
    attempts = 0

    def interrupted_close():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise interruption
        original_close()

    backend.close_error = ValueError("later resource cleanup error")
    monkeypatch.setattr(scheduler, "close", interrupted_close)
    with pytest.raises(KeyboardInterrupt) as caught:
        engine.close()
    assert caught.value is interruption
    assert attempts == 2
    engine.close()
    assert backend.close_count == 1


def test_embedding_initialization_is_shared_with_retriever_construction(
    tmp_path, capability_settings, monkeypatch, request
):
    if _run_in_subprocess(request):
        return
    entered, release = Event(), Event()
    models = object(), object()
    provider = Mock()

    def build_code(**_kwargs):
        entered.set()
        assert release.wait(5)
        return models[0]

    provider.get_embed_model_code.side_effect = build_code
    provider.get_embed_model_docs.return_value = models[1]
    backend = _LocalBackend()
    backend.embed_model_code = backend.embed_model_docs = None
    engine = _engine(
        tmp_path, capability_settings, backend, embedding_provider=provider
    )
    index = engine.capabilities["index"]
    observed = _ObservedLock(engine._state.retriever_lock)
    monkeypatch.setattr(engine._state, "retriever_lock", observed)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(index.get_embedding_models)
            try:
                assert entered.wait(5)
                second = pool.submit(index.get_retrievers)
                assert observed.contended.wait(5)
            finally:
                release.set()
            assert first.result(timeout=5) == models
            assert second.result(timeout=5) == ("code retriever", "docs retriever")
        assert index.get_embedding_models() == models
        assert (backend.embed_model_code, backend.embed_model_docs) == models
        provider.get_embed_model_code.assert_called_once()
        provider.get_embed_model_docs.assert_called_once()
    finally:
        release.set()
        engine.close()


@pytest.mark.parametrize("failure", ("code_reentry", "docs_reentry", "docs_error"))
def test_embedding_initialization_failure_leaves_no_partial_pair_and_can_retry(
    tmp_path, capability_settings, failure
):
    models = object(), object()
    provider = Mock()
    provider.get_embed_model_code.return_value = models[0]
    provider.get_embed_model_docs.return_value = models[1]
    backend = _LocalBackend()
    backend.embed_model_code = backend.embed_model_docs = None
    engine = _engine(
        tmp_path, capability_settings, backend, embedding_provider=provider
    )
    index = engine.capabilities["index"]
    failing_method = (
        provider.get_embed_model_code
        if failure == "code_reentry"
        else provider.get_embed_model_docs
    )
    failing_method.side_effect = (
        ValueError("model construction failed")
        if failure == "docs_error"
        else lambda **_kwargs: index.get_embedding_models()
    )
    try:
        with pytest.raises(
            (RuntimeError, ValueError), match="constructed|construction"
        ):
            index.get_retrievers()
        assert index._embed_model_code is None
        assert index._embed_model_docs is None
        assert backend.embed_model_code is None
        assert backend.embed_model_docs is None
        assert engine._state.retriever_code is None
        failing_method.side_effect = None
        assert index.get_retrievers() == ("code retriever", "docs retriever")
        assert index.get_embedding_models() == models
        assert (backend.embed_model_code, backend.embed_model_docs) == models
    finally:
        engine.close()


@pytest.mark.parametrize("reset_fails", (False, True))
def test_reset_invalidates_both_caches_before_and_after_backend_callbacks(
    tmp_path, capability_settings, monkeypatch, reset_fails
):
    backend = _LocalBackend()
    monkeypatch.setattr(
        backend,
        "get_retrievers",
        lambda *_args, **_kwargs: (
            (backend.reset_count, object()),
            (backend.reset_count, object()),
        ),
    )
    engine = _engine(tmp_path, capability_settings, backend)
    index = engine.capabilities["index"]
    reset = backend.reset_index

    def reset_index():
        reset()
        # A reentrant backend callback must not receive the cached old generation.
        assert index.get_retrievers()[0][0] == backend.reset_count
        assert index._retrievers_for_top_k(1)[0][0] == backend.reset_count
        if reset_fails:
            raise ValueError("reset failed after replacement")

    monkeypatch.setattr(backend, "reset_index", reset_index)
    try:
        assert index.get_retrievers()[0][0] == 0
        assert index._retrievers_for_top_k(1)[0][0] == 0
        engine._state.pending_nodes = ([], [])
        if reset_fails:
            with pytest.raises(ValueError, match="reset failed"):
                index.indexing.index_finalize_embeddings()
        else:
            index.indexing.index_finalize_embeddings()
        assert engine._state.retriever_code is None
        assert engine._state.retriever_docs is None
        assert index._retrievers_by_top_k == {}
        assert index.get_retrievers()[0][0] == 1
        assert index._retrievers_for_top_k(1)[0][0] == 1
    finally:
        engine.close()


def test_cached_retrieval_waits_for_collection_replacement(
    tmp_path, capability_settings, monkeypatch, request
):
    if _run_in_subprocess(request):
        return
    entered, release = Event(), Event()
    backend = _LocalBackend()
    monkeypatch.setattr(
        backend,
        "get_retrievers",
        lambda *_args, **_kwargs: (
            (backend.reset_count, object()),
            (backend.reset_count, object()),
        ),
    )
    engine = _engine(tmp_path, capability_settings, backend)
    index = engine.capabilities["index"]
    observed = _ObservedLock(engine._state.retriever_lock)
    monkeypatch.setattr(engine._state, "retriever_lock", observed)
    reset = backend.reset_index

    def reset_index():
        entered.set()
        assert release.wait(5)
        reset()

    def finalize():
        engine._state.pending_nodes = ([], [])
        index.indexing.index_finalize_embeddings()

    monkeypatch.setattr(backend, "reset_index", reset_index)
    try:
        index.get_retrievers()
        index._retrievers_for_top_k(1)
        with ThreadPoolExecutor(max_workers=2) as pool:
            writing = pool.submit(finalize)
            try:
                assert entered.wait(5)
                reading = pool.submit(index.get_retrievers)
                assert observed.contended.wait(5)
            finally:
                release.set()
            writing.result(timeout=5)
            assert reading.result(timeout=5)[0][0] == 1
        assert index._retrievers_for_top_k(1)[0][0] == 1
    finally:
        release.set()
        engine.close()


@pytest.mark.parametrize("top_k", (1, 3))
def test_reentrant_reset_cannot_publish_retrievers_from_the_old_generation(
    tmp_path, capability_settings, monkeypatch, top_k
):
    backend = _LocalBackend()
    engine = _engine(tmp_path, capability_settings, backend)
    index = engine.capabilities["index"]
    first_call = True

    def get_retrievers(*_args, **_kwargs):
        nonlocal first_call
        pair = (backend.reset_count, object()), (backend.reset_count, object())
        if first_call:
            first_call = False
            engine._state.pending_nodes = ([], [])
            index.indexing.index_finalize_embeddings()
        return pair

    monkeypatch.setattr(backend, "get_retrievers", get_retrievers)
    try:
        with pytest.raises(RuntimeError, match="Index changed during retriever"):
            index._retrievers_for_top_k(top_k)
        assert engine._state.retriever_code is None
        assert index._retrievers_by_top_k == {}
        assert index._retrievers_for_top_k(top_k)[0][0] == 1
    finally:
        engine.close()


def test_retriever_initialization_serializes_concurrent_cache_misses(
    tmp_path, capability_settings, request
):
    if _run_in_subprocess(request):
        return
    entered, release = Event(), Event()
    backend = _LocalBackend()

    def create(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return "code", "docs"

    backend.get_retrievers = Mock(side_effect=create)
    engine = _engine(tmp_path, capability_settings, backend)
    index = engine.capabilities["index"]
    observed = _ObservedLock(engine._state.retriever_lock)
    engine._state.retriever_lock = observed
    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(index.get_retrievers)
            try:
                assert entered.wait(5)
                second = workers.submit(index.get_retrievers)
                assert observed.contended.wait(5)
            finally:
                release.set()
            assert (
                first.result(timeout=5) == second.result(timeout=5) == ("code", "docs")
            )
        backend.get_retrievers.assert_called_once()
    finally:
        release.set()
        engine.close()
