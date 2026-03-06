# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
import tempfile
import threading
from unittest.mock import Mock
from metis.engine import MetisEngine
from metis.exceptions import PluginNotFoundError, QueryEngineInitError


def test_supported_languages():
    langs = MetisEngine.supported_languages()
    assert "c" in langs
    assert "python" in langs
    assert "rust" in langs
    assert "typescript" in langs


def test_get_existing_plugin(engine):
    plugin = engine.get_plugin_from_name("c")
    assert plugin.get_name().lower() == "c"


def test_get_missing_plugin_raises(engine):
    with pytest.raises(PluginNotFoundError):
        engine.get_plugin_from_name("nonexistent")


def test_init_and_get_query_engines_raises_on_missing_backend():
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_query_engines = Mock(return_value=(None, None))
    engine = MetisEngine(
        vector_backend=bad_backend,
        llm_provider=Mock(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    with pytest.raises(QueryEngineInitError):
        engine._init_and_get_query_engines()


def test_init_and_get_query_engines_propagates_backend_init_error():
    bad_backend = Mock()
    bad_backend.init = Mock(side_effect=RuntimeError("boom"))
    bad_backend.get_query_engines = Mock(return_value=(object(), object()))
    engine = MetisEngine(
        vector_backend=bad_backend,
        llm_provider=Mock(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    with pytest.raises(RuntimeError, match="boom"):
        engine._init_and_get_query_engines()
    assert engine._qe_code is None
    assert engine._qe_docs is None


@pytest.mark.parametrize("query_engines", [(None, object()), (object(), None)])
def test_init_and_get_query_engines_raises_on_partial_query_engines(query_engines):
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_query_engines = Mock(return_value=query_engines)
    engine = MetisEngine(
        vector_backend=bad_backend,
        llm_provider=Mock(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    with pytest.raises(QueryEngineInitError):
        engine._init_and_get_query_engines()
    assert engine._qe_code is None
    assert engine._qe_docs is None


def test_init_and_get_default_unavailable_metisignore():
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_query_engines = Mock(return_value=(None, None))
    engine = MetisEngine(
        vector_backend=bad_backend,
        llm_provider=Mock(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
        metisignore_file=".metisignore_file",
    )
    assert engine.metisignore_file == ".metisignore_file"
    assert engine.load_metisignore() is None


def test_init_and_get_default_available_metisignore():
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_query_engines = Mock(return_value=(None, None))
    engine = None
    with tempfile.NamedTemporaryFile(
        mode="w+t", encoding="utf-8", suffix=".yaml"
    ) as temp_file:
        engine = MetisEngine(
            vector_backend=bad_backend,
            llm_provider=Mock(),
            max_workers=2,
            max_token_length=2048,
            llama_query_model="gpt-test",
            similarity_top_k=3,
            response_mode="compact",
            metisignore_file=temp_file.name,
        )
        assert engine.load_metisignore() is not None
        assert engine.metisignore_file == temp_file.name
    assert engine is not None


def test_review_code_parallel_init_invokes_backend_init_once_per_engine_lifecycle(
    dummy_llm, monkeypatch
):
    parallel_calls = 4

    class _CountingBackend:
        def __init__(self):
            self.init_call_count = 0
            self.get_query_engines_call_count = 0
            self._init_barrier = threading.Barrier(parallel_calls)

        def init(self):
            self.init_call_count += 1
            try:
                self._init_barrier.wait(timeout=2)
            except threading.BrokenBarrierError:
                pass

        def get_query_engines(self, *_args, **_kwargs):
            self.get_query_engines_call_count += 1
            return (object(), object())

    backend = _CountingBackend()
    engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=backend,
        llm_provider=dummy_llm,
        max_workers=parallel_calls,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    monkeypatch.setattr(
        engine,
        "get_code_files",
        lambda: [f"/tmp/file_{i}.c" for i in range(parallel_calls)],
    )

    def _review_file(_path):
        engine._init_and_get_query_engines()
        return {"reviews": ["ok"]}

    monkeypatch.setattr(engine, "review_file", _review_file)

    results = list(engine.review_code())
    assert len(results) == parallel_calls
    assert backend.init_call_count == 1
    assert backend.get_query_engines_call_count == 1


def test_close_clears_cached_query_engines_after_concurrent_init(dummy_llm):
    init_started = threading.Event()
    release_init = threading.Event()

    class _Backend:
        def init(self):
            init_started.set()
            release_init.wait(timeout=2)

        def get_query_engines(self, *_args, **_kwargs):
            return (object(), object())

        def close(self):
            return None

    engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=_Backend(),
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    init_thread = threading.Thread(target=engine._init_and_get_query_engines)
    close_thread = threading.Thread(target=engine.close)

    init_thread.start()
    assert init_started.wait(timeout=2)
    close_thread.start()
    release_init.set()
    init_thread.join(timeout=2)
    close_thread.join(timeout=2)

    assert not init_thread.is_alive()
    assert not close_thread.is_alive()
    assert engine._qe_code is None
    assert engine._qe_docs is None


def test_init_releases_query_engine_lock_while_backend_init_runs(dummy_llm):
    init_started = threading.Event()
    release_init = threading.Event()

    class _Backend:
        def init(self):
            init_started.set()
            release_init.wait(timeout=2)

        def get_query_engines(self, *_args, **_kwargs):
            return (object(), object())

        def close(self):
            return None

    engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=_Backend(),
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    init_thread = threading.Thread(target=engine._init_and_get_query_engines)
    init_thread.start()
    assert init_started.wait(timeout=2)

    lock_was_released = engine._qe_init_lock.acquire(blocking=False)
    if lock_was_released:
        engine._qe_init_lock.release()

    release_init.set()
    init_thread.join(timeout=2)

    assert not init_thread.is_alive()
    assert lock_was_released is True


def test_close_clears_cached_query_engines_when_backend_close_fails(dummy_llm):
    qe_code = object()
    qe_docs = object()

    class _Backend:
        def init(self):
            return None

        def get_query_engines(self, *_args, **_kwargs):
            return (qe_code, qe_docs)

        def close(self):
            raise RuntimeError("close failed")

    engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=_Backend(),
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    assert engine._init_and_get_query_engines() == (qe_code, qe_docs)
    assert engine._qe_code is qe_code
    assert engine._qe_docs is qe_docs

    with pytest.raises(RuntimeError, match="close failed"):
        engine.close()

    assert engine._qe_code is None
    assert engine._qe_docs is None


def test_close_invalidates_cached_query_engines_and_reinits_on_next_access(dummy_llm):
    first_qe_code = object()
    first_qe_docs = object()
    second_qe_code = object()
    second_qe_docs = object()

    class _Backend:
        def __init__(self):
            self.init_call_count = 0
            self.close_call_count = 0
            self._next_engines = [
                (first_qe_code, first_qe_docs),
                (second_qe_code, second_qe_docs),
            ]

        def init(self):
            self.init_call_count += 1

        def get_query_engines(self, *_args, **_kwargs):
            return self._next_engines.pop(0)

        def close(self):
            self.close_call_count += 1

    backend = _Backend()
    engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    assert engine._init_and_get_query_engines() == (first_qe_code, first_qe_docs)
    assert engine._init_and_get_query_engines() == (first_qe_code, first_qe_docs)
    assert backend.init_call_count == 1

    engine.close()
    assert backend.close_call_count == 1
    assert engine._qe_code is None
    assert engine._qe_docs is None

    assert engine._init_and_get_query_engines() == (second_qe_code, second_qe_docs)
    assert backend.init_call_count == 2


def test_close_blocks_reinit_until_backend_close_completes(dummy_llm):
    close_started = threading.Event()
    release_close = threading.Event()
    init_completed = threading.Event()

    class _Backend:
        def __init__(self):
            self.init_call_count = 0

        def init(self):
            self.init_call_count += 1

        def get_query_engines(self, *_args, **_kwargs):
            return (object(), object())

        def close(self):
            close_started.set()
            release_close.wait(timeout=2)

    backend = _Backend()
    engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    engine._init_and_get_query_engines()
    assert backend.init_call_count == 1

    close_errors = []
    init_errors = []

    def _call_close():
        try:
            engine.close()
        except Exception as exc:
            close_errors.append(exc)

    def _call_init():
        try:
            engine._init_and_get_query_engines()
        except Exception as exc:
            init_errors.append(exc)
        finally:
            init_completed.set()

    close_thread = threading.Thread(target=_call_close)
    close_thread.start()
    assert close_started.wait(timeout=2)

    init_thread = threading.Thread(target=_call_init)
    init_thread.start()
    assert not init_completed.wait(timeout=0.2)

    release_close.set()
    assert init_completed.wait(timeout=2)

    assert not close_errors
    assert not init_errors
    assert backend.init_call_count == 2

    close_thread.join(timeout=2)
    init_thread.join(timeout=2)
    assert not close_thread.is_alive()
    assert not init_thread.is_alive()


def test_init_clears_in_progress_flag_on_base_exception(dummy_llm):
    first_qe_code = object()
    first_qe_docs = object()

    class _FatalInitError(BaseException):
        pass

    class _Backend:
        def __init__(self):
            self.init_call_count = 0

        def init(self):
            self.init_call_count += 1
            if self.init_call_count == 1:
                raise _FatalInitError("fatal init interruption")

        def get_query_engines(self, *_args, **_kwargs):
            return (first_qe_code, first_qe_docs)

    backend = _Backend()
    engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    with pytest.raises(_FatalInitError, match="fatal init interruption"):
        engine._init_and_get_query_engines()

    assert engine._qe_init_in_progress is False
    assert engine._init_and_get_query_engines() == (first_qe_code, first_qe_docs)
    assert backend.init_call_count == 2


def test_close_resets_close_state_when_close_lookup_fails(dummy_llm):
    first_qe_code = object()
    first_qe_docs = object()
    second_qe_code = object()
    second_qe_docs = object()

    class _Backend:
        def __init__(self):
            self.init_call_count = 0
            self._engines = [
                (first_qe_code, first_qe_docs),
                (second_qe_code, second_qe_docs),
            ]

        def __getattribute__(self, name):
            if name == "close":
                raise RuntimeError("close lookup failed")
            return object.__getattribute__(self, name)

        def init(self):
            self.init_call_count += 1

        def get_query_engines(self, *_args, **_kwargs):
            return self._engines.pop(0)

    backend = _Backend()
    engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    assert engine._init_and_get_query_engines() == (first_qe_code, first_qe_docs)

    with pytest.raises(RuntimeError, match="close lookup failed"):
        engine.close()

    assert engine._qe_close_in_progress is False
    assert engine._qe_code is None
    assert engine._qe_docs is None

    assert engine._init_and_get_query_engines() == (second_qe_code, second_qe_docs)
    assert backend.init_call_count == 2
