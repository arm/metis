# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pathspec

import metis.engine.indexing_service as indexing_service_mod
from metis.engine import MetisEngine


def _build_engine(tmp_path, dummy_backend, dummy_llm, **kwargs):
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
        enabled_tools={"index"},
        **kwargs,
    )


def test_get_code_files_supports_default_metisignore_allowlist(
    tmp_path, dummy_backend, dummy_llm
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("print('keep')\n", encoding="utf-8")
    (tmp_path / "src" / "drop.py").write_text("print('drop')\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("*\n!src/\n!src/keep.py\n", encoding="utf-8")

    engine = _build_engine(tmp_path, dummy_backend, dummy_llm)

    files = sorted(
        Path(path).relative_to(tmp_path).as_posix()
        for path in engine.repository.get_code_files()
    )
    assert files == ["src/keep.py"]


def test_count_index_items_respects_metisignore_allowlist(
    tmp_path, dummy_backend, dummy_llm
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("print('keep')\n", encoding="utf-8")
    (tmp_path / "src" / "drop.py").write_text("print('drop')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# keep\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("# drop\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text(
        "*\n!src/\n!src/keep.py\n!README.md\n", encoding="utf-8"
    )

    engine = _build_engine(tmp_path, dummy_backend, dummy_llm)

    assert engine.indexing.count_index_items() == 2


def test_index_prepare_nodes_respects_nested_metisignore_allowlist(
    tmp_path, dummy_backend, dummy_llm, monkeypatch
):
    (tmp_path / ".metisignore").write_text(
        "*\n!src/\n!src/keep.py\n!README.md\n", encoding="utf-8"
    )

    engine = _build_engine(tmp_path, dummy_backend, dummy_llm)

    documents = [
        SimpleNamespace(
            id_=str(tmp_path / "src" / "keep.py"),
            doc_id=str(tmp_path / "src" / "keep.py"),
        ),
        SimpleNamespace(
            id_=str(tmp_path / "src" / "drop.py"),
            doc_id=str(tmp_path / "src" / "drop.py"),
        ),
        SimpleNamespace(
            id_=str(tmp_path / "README.md"),
            doc_id=str(tmp_path / "README.md"),
        ),
        SimpleNamespace(
            id_=str(tmp_path / "notes.md"),
            doc_id=str(tmp_path / "notes.md"),
        ),
    ]

    class _DummyReader:
        def __init__(self, **_kwargs):
            pass

        def load_data(self):
            return list(documents)

    captured = {}

    def _fake_prepare_nodes_iter(code_docs, doc_docs, *_args):
        captured["code_ids"] = [doc.id_ for doc in code_docs]
        captured["doc_ids"] = [doc.id_ for doc in doc_docs]
        if False:
            yield None
        return (["code-node"], ["doc-node"])

    monkeypatch.setattr(indexing_service_mod, "SimpleDirectoryReader", _DummyReader)
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
    tmp_path, dummy_backend, dummy_llm, monkeypatch
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

    engine = _build_engine(tmp_path, dummy_backend, dummy_llm)
    reviewed = []

    class _DummyReviewGraph:
        def review(self, req):
            reviewed.append(req["relative_file"])
            return {
                "file": req["relative_file"],
                "reviews": [{"issue": f"issue in {req['relative_file']}"}],
            }

    import metis.engine.review_service as review_service_mod

    monkeypatch.setattr(engine, "_get_review_graph", lambda: _DummyReviewGraph())
    monkeypatch.setattr(
        review_service_mod, "summarize_changes", lambda *args, **kwargs: "summary"
    )

    result = engine.review.review_patch(str(patch_file))

    assert reviewed == ["src/keep.py"]
    assert [review["file"] for review in result["reviews"]] == ["src/keep.py"]
    assert result["overall_changes"] == "summary"


def test_concurrent_review_selection_reuses_compiled_scopes(
    tmp_path, dummy_backend, dummy_llm, monkeypatch
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


def test_review_scope_cache_observes_ordered_pattern_changes(
    tmp_path, dummy_backend, dummy_llm
):
    names = {"first.py", "second.py", "third.py"}
    for name in names:
        (tmp_path / name).touch()
    engine = _build_engine(
        tmp_path,
        dummy_backend,
        dummy_llm,
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
