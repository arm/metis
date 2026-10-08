# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import errno
import os
import threading

import pathspec
import pytest

import metis.engine.capabilities.indexing as indexing_service_mod
from metis.engine import MetisEngine
from metis.engine.nodes.simple_llm_review.service import SimpleLlmReviewService


def _build_engine(
    tmp_path,
    dummy_backend,
    dummy_llm,
    capability_settings,
    **kwargs,
):
    class _EmbeddingProvider:
        def get_embed_model_code(self, **_kwargs):
            return object()

        def get_embed_model_docs(self, **_kwargs):
            return object()

    return MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        embedding_provider=_EmbeddingProvider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        capability_settings=capability_settings,
        **kwargs,
    )


def test_get_code_files_supports_default_metisignore_allowlist(
    tmp_path, dummy_backend, dummy_llm, capability_settings
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("print('keep')\n", encoding="utf-8")
    (tmp_path / "src" / "drop.py").write_text("print('drop')\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("*\n!src/\n!src/keep.py\n", encoding="utf-8")

    engine = _build_engine(tmp_path, dummy_backend, dummy_llm, capability_settings)

    files = sorted(
        Path(path).relative_to(tmp_path).as_posix()
        for path in engine.repository.get_code_files()
    )
    assert files == ["src/keep.py"]


def test_direct_code_file_selection_respects_metisignore(
    tmp_path, dummy_backend, dummy_llm, capability_settings
):
    (tmp_path / "keep.py").write_text("print('keep')\n", encoding="utf-8")
    (tmp_path / "drop.py").write_text("print('drop')\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("drop.py\n", encoding="utf-8")
    engine = _build_engine(tmp_path, dummy_backend, dummy_llm, capability_settings)

    assert engine.repository.is_code_file_selected("keep.py") is True
    assert engine.repository.is_code_file_selected("drop.py") is False


def test_concurrent_review_selection_reuses_compiled_scopes(
    tmp_path, dummy_backend, dummy_llm, capability_settings, monkeypatch
):
    names = [f"selected-{index}.py" for index in range(16)]
    for name in [*names, "omitted.py"]:
        (tmp_path / name).touch()
    (tmp_path / ".metisignore").write_text("/omitted.py\n", encoding="utf-8")
    includes = [f"/selected-{index}.py" for index in range(1024)]
    engine = _build_engine(
        tmp_path,
        dummy_backend,
        dummy_llm,
        capability_settings,
        review_code_include_paths=includes,
        review_code_exclude_paths=["/never.py"],
    )
    compiled = []
    from_lines = pathspec.GitIgnoreSpec.from_lines

    def compile_spec(lines, **kwargs):
        patterns = tuple(lines)
        compiled.append(patterns)
        assert kwargs == {"backend": "simple"}
        return from_lines(patterns, **kwargs)

    monkeypatch.setattr(pathspec.GitIgnoreSpec, "from_lines", compile_spec)
    with ThreadPoolExecutor(max_workers=4) as pool:
        inventories = list(
            pool.map(lambda _: engine.repository.get_code_files(), range(8))
        )

    expected = sorted(str(tmp_path / name) for name in names)
    assert all(sorted(files) == expected for files in inventories)
    assert compiled == [("/omitted.py\n",), tuple(includes), ("/never.py",)]
    assert engine.repository.is_code_file_selected(names[0])
    assert len(compiled) == 3


def test_review_scope_cache_observes_ordered_pattern_changes(
    tmp_path, dummy_backend, dummy_llm, capability_settings
):
    names = {"first.py", "second.py", "third.py"}
    for name in names:
        (tmp_path / name).touch()
    engine = _build_engine(
        tmp_path,
        dummy_backend,
        dummy_llm,
        capability_settings,
        review_code_include_paths=["*.py", "!second.py"],
        review_code_exclude_paths=["third.py"],
    )

    def selected():
        return {Path(path).name for path in engine.repository.get_code_files()}

    assert selected() == {"first.py"}
    engine._config.review_code_include_paths.append("second.py")
    assert selected() == {"first.py", "second.py"}
    engine._config.review_code_exclude_paths[:] = ["*.py", "!second.py"]
    assert selected() == {"second.py"}
    engine._config.review_code_include_paths = ["first.py"]
    assert selected() == set()
    engine._config.review_code_exclude_paths = []
    assert selected() == {"first.py"}
    engine._config.review_code_include_paths = []
    assert selected() == names
    engine._config.review_code_include_paths = ["# comment"]
    assert selected() == set()


@pytest.mark.parametrize(
    "name",
    [
        "unicode-文.py",
        pytest.param(
            "undecodable-\udcff.py",
            marks=pytest.mark.skipif(os.name == "nt", reason="POSIX byte filename"),
        ),
    ],
)
def test_review_scope_preserves_unicode_and_literal_matching(
    tmp_path, dummy_backend, dummy_llm, capability_settings, name
):
    try:
        (tmp_path / name).touch()
    except OSError as exc:
        if exc.errno == errno.EILSEQ and "\udcff" in name:
            pytest.skip("Filesystem does not support undecodable byte filenames")
        raise
    for filename in ("bracket[one].py", "bracketo.py", "ignored.py"):
        (tmp_path / filename).touch()
    (tmp_path / ".metisignore").write_text("/ignored.py\n", encoding="utf-8")
    engine = _build_engine(
        tmp_path,
        dummy_backend,
        dummy_llm,
        capability_settings,
        review_code_include_paths=["*.py"],
        review_code_exclude_paths=[
            "*.py",
            "!unicode-*.py",
            "!undecodable-*.py",
            r"!bracket\[one\].py",
            "!ignored.py",
        ],
    )

    assert {Path(path).name for path in engine.repository.get_code_files()} == {
        name,
        "bracket[one].py",
    }


def test_perl_files_follow_repository_review_selection_rules(
    tmp_path, dummy_backend, dummy_llm, capability_settings
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.pl").write_text("print qq(keep\\n);\n", encoding="utf-8")
    (tmp_path / "src" / "app.psgi").write_text(
        "sub { [200, [], ['ok']] };\n", encoding="utf-8"
    )
    (tmp_path / "src" / "ignored.pm").write_text("package Ignored;\n", encoding="utf-8")
    (tmp_path / "src" / "excluded.t").write_text("use Test::More;\n", encoding="utf-8")
    (tmp_path / "src" / "legacy.cgi").write_text(
        "print qq(legacy);\n", encoding="utf-8"
    )
    (tmp_path / "outside.pm").write_text("package Outside;\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("src/ignored.pm\n", encoding="utf-8")

    engine = _build_engine(
        tmp_path,
        dummy_backend,
        dummy_llm,
        capability_settings,
        review_code_include_paths=["src/"],
        review_code_exclude_paths=["src/excluded.t"],
    )

    files = sorted(
        Path(path).relative_to(tmp_path).as_posix()
        for path in engine.repository.get_code_files(include_suffixed_sources=True)
    )

    assert files == ["src/app.psgi", "src/keep.pl"]


def test_concurrent_metisignore_load_waits_for_initialized_spec(
    tmp_path,
    dummy_backend,
    dummy_llm,
    capability_settings,
    monkeypatch,
):
    metisignore = tmp_path / ".metisignore"
    metisignore.write_text("drop.py\n", encoding="utf-8")
    engine = _build_engine(tmp_path, dummy_backend, dummy_llm, capability_settings)
    real_open = open
    opened = threading.Event()
    release = threading.Event()
    second_finished = threading.Event()
    results = []

    def slow_open(path, *args, **kwargs):
        if Path(path) == metisignore:
            opened.set()
            release.wait(timeout=2)
        return real_open(path, *args, **kwargs)

    def load_first() -> None:
        results.append(engine.repository.load_metisignore())

    def load_second() -> None:
        results.append(engine.repository.load_metisignore())
        second_finished.set()

    monkeypatch.setattr("builtins.open", slow_open)
    first = threading.Thread(target=load_first)
    second = threading.Thread(target=load_second)
    first.start()
    assert opened.wait(timeout=1)
    second.start()
    assert not second_finished.wait(timeout=0.05)
    release.set()
    first.join(timeout=1)
    second.join(timeout=1)

    assert len(results) == 2
    assert all(spec is not None for spec in results)


def test_count_index_items_respects_metisignore_allowlist(
    tmp_path, dummy_backend, dummy_llm, capability_settings
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("print('keep')\n", encoding="utf-8")
    (tmp_path / "src" / "drop.py").write_text("print('drop')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# keep\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("# drop\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text(
        "*\n!src/\n!src/keep.py\n!README.md\n", encoding="utf-8"
    )

    engine = _build_engine(tmp_path, dummy_backend, dummy_llm, capability_settings)

    assert engine.indexing.count_index_items() == 2


def test_index_prepare_nodes_respects_nested_metisignore_allowlist(
    tmp_path,
    dummy_backend,
    dummy_llm,
    monkeypatch,
    capability_settings,
):
    (tmp_path / ".metisignore").write_text(
        "*\n!src/\n!src/keep.py\n!README.md\n", encoding="utf-8"
    )

    engine = _build_engine(tmp_path, dummy_backend, dummy_llm, capability_settings)

    for name in ("src/keep.py", "src/drop.py", "README.md", "notes.md"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("inert text\n", encoding="utf-8")

    captured = {}

    def _fake_prepare_nodes_iter(code_docs, doc_docs, *_args):
        captured["code_ids"] = [doc.id_ for doc in code_docs]
        captured["doc_ids"] = [doc.id_ for doc in doc_docs]
        if False:
            yield None
        return (["code-node"], ["doc-node"])

    monkeypatch.setattr(
        indexing_service_mod, "prepare_nodes_iter", _fake_prepare_nodes_iter
    )

    engine.indexing.index_prepare_nodes()

    assert captured == {
        "code_ids": [f"{tmp_path.name}/src/keep.py"],
        "doc_ids": [f"{tmp_path.name}/README.md"],
    }
    assert engine._state.pending_nodes == (["code-node"], ["doc-node"])


def test_review_patch_respects_metisignore_allowlist(
    tmp_path, dummy_backend, dummy_llm, monkeypatch, capability_settings
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("print('keep')\n", encoding="utf-8")
    (tmp_path / "src" / "drop.py").write_text("print('drop')\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("*\n!src/\n!src/keep.py\n", encoding="utf-8")

    patch = """--- a/src/keep.py
+++ b/src/keep.py
@@ -1 +1,2 @@
 print('keep')
+print('still-keep')
--- a/src/drop.py
+++ b/src/drop.py
@@ -1 +1,2 @@
 print('drop')
+print('should-not-review')
"""
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(patch, encoding="utf-8")

    engine = _build_engine(tmp_path, dummy_backend, dummy_llm, capability_settings)
    reviewed = []

    class _DummyReviewGraph:
        def review(self, req):
            reviewed.append(req["relative_file"])
            return {
                "file": req["relative_file"],
                "reviews": [{"issue": f"issue in {req['relative_file']}"}],
            }

    import metis.engine.nodes.simple_llm_review.service as review_service_mod

    monkeypatch.setattr(
        engine,
        "_get_review_graph",
        lambda _index=None, _model=None: _DummyReviewGraph(),
    )
    monkeypatch.setattr(
        review_service_mod, "summarize_changes", lambda *args, **kwargs: "summary"
    )

    service = SimpleLlmReviewService(
        engine._config,
        engine.repository,
        lambda index, model: engine._get_review_graph(index, model),
    )
    result = service.review_patch(str(patch_file))

    assert reviewed == ["src/keep.py"]
    assert [review["file"] for review in result["reviews"]] == ["src/keep.py"]
    assert result["overall_changes"] == "summary"
