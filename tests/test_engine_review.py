# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock


def test_ask_question(engine):
    result = engine.ask_question("What is this?")
    assert "code" in result
    assert "docs" in result


def test_review_code_runs(engine):
    engine.review_file = Mock(return_value={"file": "test.py", "reviews": ["Issue"]})
    results = list(engine.review_code())
    assert len(results) >= 1
    assert all("reviews" in r for r in results)


def test_review_patch_parses_and_reviews(engine):
    patch = """\
        --- a/test.py
        +++ b/test.py
        @@ -0,0 +1,2 @@
        +print('Hello')
        +print('World')
        """
    engine._process_file_reviews = Mock(
        return_value={"file": "test.py", "reviews": ["Issue"]}
    )
    result = engine.review_patch(patch)
    assert "reviews" in result


def test_review_patch_handles_parse_error(engine):
    bad_patch = "INVALID PATCH FORMAT"
    result = engine.review_patch(bad_patch)
    assert "reviews" in result
    assert result["reviews"] == []
