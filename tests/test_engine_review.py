# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from metis.cli.commands import run_review_code
from metis.cli.commands import run_index
from metis.engine import MetisEngine


def test_ask_question(engine):
    result = engine.ask_question("What is this?")
    assert "code" in result
    assert "docs" in result


def test_review_code_runs(engine):
    engine.review_file = Mock(return_value={"file": "test.py", "reviews": ["Issue"]})
    results = list(engine.review_code())
    assert len(results) >= 1
    assert all("reviews" in r for r in results)


def test_review_patch_parses_and_reviews(engine, monkeypatch, tmp_path):
    patch = """--- a/test.py
+++ b/test.py
@@ -0,0 +1,2 @@
+print('Hello')
+print('World')
"""

    # Write patch to a temporary file because review_patch expects a file path
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(patch)

    # Stub the ReviewGraph used internally so we don't rely on LLMs
    class _DummyReviewGraph:
        def review(self, _req):
            return {"file": "test.py", "reviews": [{"issue": "Issue"}]}

    monkeypatch.setattr(engine, "_get_review_graph", lambda: _DummyReviewGraph())

    # Ensure summaries are simple strings, not Mocks
    import metis.engine.core as coremod

    monkeypatch.setattr(coremod, "summarize_changes", lambda *a, **k: "summary")

    result = engine.review_patch(str(patch_file))
    assert "reviews" in result and isinstance(result["reviews"], list)
    assert any(r.get("file") == "test.py" for r in result["reviews"])


def test_review_patch_handles_parse_error(engine, tmp_path):
    bad_patch_file = tmp_path / "bad.diff"
    bad_patch_file.write_text("INVALID PATCH FORMAT")
    result = engine.review_patch(str(bad_patch_file))
    assert "reviews" in result
    assert result["reviews"] == []


@pytest.mark.parametrize("max_workers", [1, 10])
def test_index_then_non_interactive_review_code_avoids_chroma_init_race(
    dummy_llm, monkeypatch, max_workers
):
    shared_state = {"indexed": False}
    init_guard_lock = threading.Lock()
    init_started = threading.Event()
    release_init = threading.Event()
    init_call_count = 0

    index_backend = Mock()
    index_engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=index_backend,
        llm_provider=dummy_llm,
        max_workers=1,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    def _mark_indexed():
        shared_state["indexed"] = True

    monkeypatch.setattr(index_engine, "index_codebase", _mark_indexed)
    run_index(index_engine, verbose=False, quiet=True)
    assert shared_state["indexed"] is True

    review_backend = Mock()
    review_backend.get_query_engines = Mock(return_value=(object(), object()))
    review_engine = MetisEngine(
        codebase_path="./tests/data",
        vector_backend=review_backend,
        llm_provider=dummy_llm,
        max_workers=max_workers,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    def _init_with_single_call_guard():
        nonlocal init_call_count
        if not shared_state["indexed"]:
            raise RuntimeError("default_tenant connection error")
        with init_guard_lock:
            init_call_count += 1
            current_call_count = init_call_count
        if current_call_count == 1:
            init_started.set()
            release_init.wait(timeout=2)
            return
        raise RuntimeError("default_tenant connection error")

    class _DummyReviewGraph:
        def review(self, req):
            return {"file": req["relative_file"], "reviews": [{"issue": "Issue"}]}

    captured_results: dict[str, dict[str, list[dict[str, object]]]] = {}
    file_path = "./tests/data/test.c"
    review_files = [file_path for _ in range(max_workers)]

    monkeypatch.setattr(review_backend, "init", _init_with_single_call_guard)
    monkeypatch.setattr(review_engine, "get_code_files", lambda: review_files)
    monkeypatch.setattr(review_engine, "_get_review_graph", lambda: _DummyReviewGraph())
    monkeypatch.setattr(
        "metis.cli.commands.pretty_print_reviews",
        lambda results, _quiet: captured_results.setdefault("value", results),
    )
    monkeypatch.setattr(
        "metis.cli.commands.save_output", lambda *_args, **_kwargs: None
    )

    args = SimpleNamespace(verbose=False, quiet=True, output_file=[])

    def _release_after_init_starts():
        init_started.wait(timeout=2)
        release_init.set()

    release_thread = threading.Thread(target=_release_after_init_starts)
    release_thread.start()
    run_review_code(review_engine, args)
    release_thread.join(timeout=2)

    assert init_started.is_set()
    assert not release_thread.is_alive()
    assert init_call_count == 1
    assert len(captured_results["value"]["reviews"]) == max_workers
