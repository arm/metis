# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

import pytest

from metis.engine.review_validation import (
    parse_review_validation_response,
    rescue_filtered_duplicate_cluster_representatives,
    review_validation_final_keep,
)
from metis.engine.review_reachability import ReachabilityReviewBackend


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


def _reachability(engine, result=None):
    reachability = Mock()
    reachability.review_codebase.return_value = result or []
    reachability.adjudicate_final_findings = None
    engine.review._reachability_backend = ReachabilityReviewBackend(
        engine.review._config,
        engine.review._repository,
        reachability,
        {},
    )
    return reachability


def test_review_code_uses_reachability_for_c_cpp(engine):
    reachability = _reachability(
        engine,
        [{"file": "test.c", "reviews": [{"issue": "Issue", "confidence": "High"}]}],
    )
    engine.review.review_file = Mock(
        return_value={"file": "test.c", "reviews": ["legacy"]}
    )

    results = list(engine.review.review_code(get_code_files_func=lambda: ["test.c"]))

    assert results == [
        {"file": "test.c", "reviews": [{"issue": "Issue", "confidence": "High"}]}
    ]
    reachability.review_codebase.assert_called_once()
    options = reachability.review_codebase.call_args.kwargs["options"]
    assert options.lens_profile == "review"
    assert options.confirm_paths is False
    engine.review.review_file.assert_not_called()


def test_review_file_uses_focused_reachability_when_global_cache_empty(engine):
    expected = {"file": "test.c", "reviews": [{"issue": "focused"}]}
    reachability = _reachability(engine)
    reachability.review_file.return_value = expected
    engine.review._review_file_standard = Mock(
        return_value={"file": "test.c", "reviews": ["legacy"]}
    )

    result = engine.review.review_file("./tests/data/test.c")

    assert result == expected
    reachability.review_file.assert_called_once()
    reachability.review_codebase.assert_not_called()
    engine.review._review_file_standard.assert_not_called()


def test_review_code_uses_legacy_for_non_c_cpp(engine):
    reachability = _reachability(
        engine,
        [{"file": "ignored.c", "reviews": [{"issue": "Issue"}]}],
    )
    engine.review.review_file = Mock(
        return_value={"file": "test.py", "reviews": ["legacy"]}
    )

    results = list(engine.review.review_code(get_code_files_func=lambda: ["test.py"]))

    assert results == [{"file": "test.py", "reviews": ["legacy"]}]
    reachability.review_codebase.assert_not_called()
    engine.review.review_file.assert_called_once()


def test_review_code_validates_reachability_results_before_returning(engine):
    _reachability(
        engine,
        [
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
        ],
    )
    engine.review._validate_review_candidates = Mock(
        return_value=[
            {"index": 0, "keep": True, "confidence": 0.91, "reason": "concrete"},
            {
                "index": 1,
                "keep": False,
                "confidence": 0.21,
                "drop_reason": "unsupported_speculation",
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
    assert filtered[0]["review_validation_drop_reason"] == "unsupported_speculation"
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
            "drop_reason": "duplicate",
            "reason": "duplicate of stronger candidate",
        },
        {
            "index": 1,
            "keep": False,
            "confidence": 0.5,
            "drop_reason": "duplicate",
            "reason": "same root cause duplicate",
        },
    ]

    kept = [
        decision
        for decision in rescue_filtered_duplicate_cluster_representatives(
            candidates, decisions
        )
        if decision["keep"]
    ]

    assert len(kept) == 1
    assert kept[0]["index"] == 0
    assert kept[0]["confidence"] >= 0.9
    assert "strongest representative" in kept[0]["reason"]


@pytest.mark.parametrize(
    ("candidate", "decision", "expected"),
    [
        (
            {
                "issue": "Unchecked addition can wrap the page count before indexing an array",
                "severity": "High",
                "confidence": 0.75,
                "root_cause": "integer overflow in page range calculation",
                "evidence": "nr_pages = offset + size",
            },
            {
                "index": 0,
                "keep": False,
                "confidence": 0.42,
                "reason": "Security impact is not fully established.",
            },
            True,
        ),
        (
            {
                "issue": "Unchecked addition can wrap before indexing an array",
                "severity": "High",
                "confidence": 0.95,
                "root_cause": "integer overflow in page range calculation",
                "evidence": "nr_pages = offset + size",
            },
            {
                "index": 0,
                "keep": False,
                "confidence": 0.2,
                "drop_reason": "false_positive",
                "reason": "The value is already bounds-checked before use.",
            },
            False,
        ),
    ],
)
def test_review_validation_guardrails(candidate, decision, expected):
    assert review_validation_final_keep(candidate, decision) is expected


def test_review_validation_parser_accepts_double_encoded_json():
    parsed = parse_review_validation_response(
        '"{\\"decisions\\":[{\\"index\\":0,\\"keep\\":true,'
        '\\"confidence\\":0.82,\\"drop_reason\\":\\"\\",\\"reason\\":\\"ok\\"}]}"'
    )
    assert parsed == {
        "decisions": [
            {
                "index": 0,
                "keep": True,
                "confidence": 0.82,
                "drop_reason": "",
                "reason": "ok",
            }
        ]
    }


class _DummyReviewGraph:
    def __init__(self, review):
        self._review = review

    def review(self, req):
        if self._review is None:
            return {"file": "test.py", "reviews": []}
        return self._review


def test_review_patch_parses_and_reviews(engine, monkeypatch, tmp_path):
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(
        "--- a/test.py\n+++ b/test.py\n@@ -0,0 +1,2 @@\n+print('Hello')\n+print('World')\n"
    )
    monkeypatch.setattr(
        engine,
        "_get_review_graph",
        lambda: _DummyReviewGraph({"file": "test.py", "reviews": [{"issue": "Issue"}]}),
    )

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
