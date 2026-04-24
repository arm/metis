# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

from metis.engine.analysis.static_inventory import build_static_inventory
from metis.engine.options import ReviewOptions


def test_ask_question(engine):
    result = engine.ask_question("What is this?")
    assert "code" in result
    assert "docs" in result


def test_review_code_runs(engine):
    engine.review.review_file = Mock(
        return_value={"file": "test.py", "reviews": ["Issue"]}
    )
    results = list(engine.review.review_code())
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
    import metis.engine.review_service as review_service_mod

    monkeypatch.setattr(
        review_service_mod, "summarize_changes", lambda *a, **k: "summary"
    )

    result = engine.review.review_patch(str(patch_file))
    assert "reviews" in result and isinstance(result["reviews"], list)
    assert any(r.get("file") == "test.py" for r in result["reviews"])


def test_review_patch_handles_parse_error(engine, tmp_path):
    bad_patch_file = tmp_path / "bad.diff"
    bad_patch_file.write_text("INVALID PATCH FORMAT")
    result = engine.review.review_patch(str(bad_patch_file))
    assert "reviews" in result
    assert result["reviews"] == []


def test_review_file_no_index_skips_query_engine_init(engine, monkeypatch, tmp_path):
    sample = tmp_path / "sample.c"
    sample.write_text("int main(){return 0;}", encoding="utf-8")

    class _DummyReviewGraph:
        def review(self, req):
            assert req["use_retrieval_context"] is False
            assert req["retriever_code"] is None
            assert req["retriever_docs"] is None
            return {"file": "sample.c", "reviews": []}

    engine.vector_backend.get_query_engines.reset_mock()
    monkeypatch.setattr(engine, "_get_review_graph", lambda: _DummyReviewGraph())

    result = engine.review.review_file(str(sample), use_retrieval_context=False)

    assert result["reviews"] == []
    engine.vector_backend.get_query_engines.assert_not_called()


def test_review_file_static_inventory_uses_packets(engine, monkeypatch, tmp_path):
    sample = tmp_path / "sample.c"
    sample.write_text(
        "int handle_packet(char *dst, const char *src, int len) {\n"
        "    memcpy(dst, src, len);\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    engine._config.codebase_path = str(tmp_path)
    captured = {}

    class _DummyReviewGraph:
        def review(self, req):
            captured["snippet"] = req["snippet"]
            captured["relative_file"] = req["relative_file"]
            captured["review_input_kind"] = req["review_input_kind"]
            return {"file": "sample.c", "reviews": []}

    monkeypatch.setattr(engine, "_get_review_graph", lambda: _DummyReviewGraph())

    result = engine.review.review_file(
        str(sample),
        options=ReviewOptions(use_retrieval_context=False),
    )

    assert result["reviews"] == []
    assert captured["relative_file"] == "sample.c"
    assert captured["review_input_kind"] == "static_inventory_packets"
    assert "STATIC_REVIEW_PACKET" in captured["snippet"]
    assert "handle_packet" in captured["snippet"]
    assert "bounds_or_capacity" in captured["snippet"]


def test_review_file_static_inventory_skips_low_risk_file(
    engine, monkeypatch, tmp_path
):
    sample = tmp_path / "sample.c"
    sample.write_text(
        "int add_one(int value) {\n    return value + 1;\n}",
        encoding="utf-8",
    )
    engine._config.codebase_path = str(tmp_path)
    review_graph = Mock()
    monkeypatch.setattr(engine, "_get_review_graph", lambda: review_graph)

    result = engine.review.review_file(
        str(sample),
        options=ReviewOptions(use_retrieval_context=False),
    )

    assert result == {"file": "sample.c", "file_path": str(sample), "reviews": []}
    review_graph.review.assert_not_called()


def test_review_file_stale_static_inventory_rebuilds_and_uses_packets(
    engine, monkeypatch, tmp_path
):
    sample = tmp_path / "sample.c"
    sample.write_text(
        "int handle_packet(char *dst, const char *src, int len) {\n"
        "    memcpy(dst, src, len);\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    engine._config.codebase_path = str(tmp_path)
    build_static_inventory(
        engine.repository,
        output_path=tmp_path / ".metis" / "static_inventory.json",
    )
    sample.write_text(
        "int handle_packet(char *dst, const char *src, int len) {\n"
        "    helper(len);\n"
        "    memcpy(dst, src, len);\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    captured = {}

    class _DummyReviewGraph:
        def review(self, req):
            captured["snippet"] = req["snippet"]
            captured["review_input_kind"] = req["review_input_kind"]
            return {"file": "sample.c", "reviews": []}

    monkeypatch.setattr(engine, "_get_review_graph", lambda: _DummyReviewGraph())

    result = engine.review.review_file(
        str(sample),
        options=ReviewOptions(use_retrieval_context=False),
    )

    assert result["reviews"] == []
    assert captured["review_input_kind"] == "static_inventory_packets"
    assert "STATIC_REVIEW_PACKET" in captured["snippet"]
    assert "helper(len);" in captured["snippet"]


def test_review_patch_builds_static_inventory_sidecar(engine, monkeypatch, tmp_path):
    patch = """--- a/test.py
+++ b/test.py
@@ -0,0 +1 @@
+print('Hello')
"""
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(patch, encoding="utf-8")
    engine._config.codebase_path = str(tmp_path)

    class _DummyReviewGraph:
        def review(self, req):
            return {"file": "test.py", "reviews": []}

    monkeypatch.setattr(engine, "_get_review_graph", lambda: _DummyReviewGraph())

    result = engine.review.review_patch(str(patch_file), use_retrieval_context=False)

    assert isinstance(result["reviews"], list)
    assert (tmp_path / ".metis" / "static_inventory.json").exists()


def test_review_patch_no_index_skips_query_engine_init(engine, monkeypatch, tmp_path):
    patch = """--- a/test.py
+++ b/test.py
@@ -0,0 +1 @@
+print('Hello')
"""
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(patch, encoding="utf-8")

    class _DummyReviewGraph:
        def review(self, req):
            assert req["use_retrieval_context"] is False
            assert req["retriever_code"] is None
            assert req["retriever_docs"] is None
            return {"file": "test.py", "reviews": []}

    engine.vector_backend.get_query_engines.reset_mock()
    monkeypatch.setattr(engine, "_get_review_graph", lambda: _DummyReviewGraph())

    result = engine.review.review_patch(str(patch_file), use_retrieval_context=False)

    assert isinstance(result["reviews"], list)
    engine.vector_backend.get_query_engines.assert_not_called()
