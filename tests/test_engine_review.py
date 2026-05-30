# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

from metis.engine.review_service import (
    _parse_review_validation_response,
    _rescue_filtered_duplicate_cluster_representatives,
)


def test_ask_question(engine):
    result = engine.ask_question("What is this?")
    assert "code" in result
    assert "docs" in result


def test_review_code_runs(engine):
    engine.review.review_file = Mock(
        return_value={"file": "test.py", "reviews": ["Issue"]}
    )
    results = list(engine.review.review_code(get_code_files_func=lambda: ["test.py"]))
    assert len(results) >= 1
    assert all("reviews" in r for r in results)


def test_review_code_uses_reachability_for_c_cpp(engine):
    reachability = Mock()
    reachability.review_codebase.return_value = [
        {"file": "test.c", "reviews": [{"issue": "Issue", "confidence": "High"}]}
    ]
    engine.review._reachability_service = reachability
    engine.review._reachability_cache = None
    engine.review.review_file = Mock(
        return_value={"file": "test.c", "reviews": ["legacy"]}
    )

    results = list(engine.review.review_code(get_code_files_func=lambda: ["test.c"]))

    assert results == [
        {"file": "test.c", "reviews": [{"issue": "Issue", "confidence": "High"}]}
    ]
    reachability.review_codebase.assert_called_once()
    assert reachability.review_codebase.call_args.kwargs["lens_profile"] == "review"
    assert reachability.review_codebase.call_args.kwargs["confirm_paths"] is False
    engine.review.review_file.assert_not_called()


def test_review_file_uses_focused_reachability_when_global_cache_empty(engine):
    reachability = Mock()
    expected = {"file": "test.c", "reviews": [{"issue": "focused"}]}
    reachability.review_file.return_value = expected
    engine.review._reachability_service = reachability
    engine.review._reachability_cache = None
    engine.review._review_file_standard = Mock(
        return_value={"file": "test.c", "reviews": ["legacy"]}
    )

    result = engine.review.review_file("./tests/data/test.c")

    assert result == expected
    reachability.review_file.assert_called_once()
    reachability.review_codebase.assert_not_called()
    engine.review._review_file_standard.assert_not_called()


def test_review_code_uses_legacy_for_non_c_cpp(engine):
    reachability = Mock()
    reachability.review_codebase.return_value = [
        {"file": "ignored.c", "reviews": [{"issue": "Issue"}]}
    ]
    engine.review._reachability_service = reachability
    engine.review._reachability_cache = None
    engine.review.review_file = Mock(
        return_value={"file": "test.py", "reviews": ["legacy"]}
    )

    results = list(engine.review.review_code(get_code_files_func=lambda: ["test.py"]))

    assert results == [{"file": "test.py", "reviews": ["legacy"]}]
    reachability.review_codebase.assert_not_called()
    engine.review.review_file.assert_called_once()


def test_review_code_validates_reachability_results_before_returning(engine):
    reachability = Mock()
    reachability._adjudicate_final_findings = None
    reachability.review_codebase.return_value = [
        {
            "file": "test.c",
            "reviews": [
                {
                    "issue": "real",
                    "primary_file": "test.c",
                    "primary_function": "target",
                    "line_number": 10,
                    "analysis_type": "reachability",
                    "severity": "High",
                    "confidence": 0.7,
                    "reasoning": "Root cause: concrete bug",
                },
                {
                    "issue": "fake",
                    "primary_file": "test.c",
                    "primary_function": "target",
                    "line_number": 11,
                    "analysis_type": "reachability",
                    "severity": "Medium",
                    "confidence": 0.8,
                    "reasoning": "Root cause: speculative concern",
                },
            ],
        }
    ]
    engine.review._reachability_service = reachability
    engine.review._reachability_cache = None
    engine.review._validate_review_candidates = Mock(
        return_value=[
            {
                "index": 0,
                "keep": True,
                "confidence": 0.91,
                "reason": "concrete",
            },
            {
                "index": 1,
                "keep": False,
                "confidence": 0.21,
                "reason": "speculative",
            },
        ]
    )

    results = list(engine.review.review_code(get_code_files_func=lambda: ["test.c"]))

    assert len(results) == 1
    assert [item["issue"] for item in results[0]["reviews"]] == ["real"]
    assert results[0]["reviews"][0]["confidence"] == 0.91
    assert results[0]["reviews"][0]["review_validation_keep"] is True
    filtered = results[0]["review_validation_filtered_reviews"]
    assert [item["issue"] for item in filtered] == ["fake"]
    assert filtered[0]["review_validation_reason"] == "speculative"


def test_review_validation_rescues_duplicate_cluster_representative():
    candidates = [
        {
            "index": 0,
            "issue": "queue use after free",
            "primary_file": "driver.c",
            "primary_function": "delete_queue",
            "line_number": 42,
            "severity": "High",
            "confidence": 0.9,
            "cwe": "CWE-416",
        },
        {
            "index": 1,
            "issue": "queue callback use after free",
            "primary_file": "driver.c",
            "primary_function": "delete_queue",
            "line_number": 42,
            "severity": "High",
            "confidence": 0.85,
            "cwe": "CWE-416",
        },
    ]
    decisions = [
        {
            "index": 0,
            "keep": False,
            "confidence": 0.4,
            "reason": "duplicate of stronger candidate",
        },
        {
            "index": 1,
            "keep": False,
            "confidence": 0.5,
            "reason": "same root cause duplicate",
        },
    ]

    rescued = _rescue_filtered_duplicate_cluster_representatives(
        candidates, decisions
    )

    kept = [decision for decision in rescued if decision["keep"]]
    assert len(kept) == 1
    assert kept[0]["index"] == 0
    assert kept[0]["confidence"] >= 0.9
    assert "strongest representative" in kept[0]["reason"]


def test_review_validation_parser_accepts_double_encoded_json():
    parsed = _parse_review_validation_response(
        '"{\\"decisions\\":[{\\"index\\":0,\\"keep\\":true,'
        '\\"confidence\\":0.82,\\"reason\\":\\"ok\\"}]}"'
    )

    assert parsed == {
        "decisions": [
            {
                "index": 0,
                "keep": True,
                "confidence": 0.82,
                "reason": "ok",
            }
        ]
    }


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
