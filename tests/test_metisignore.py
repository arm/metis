# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from types import SimpleNamespace

import metis.engine.indexing_service as indexing_service_mod
from metis.engine import MetisEngine


def _build_engine(tmp_path, dummy_backend, dummy_llm):
    return MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
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
