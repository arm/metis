# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Any
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda

from metis.engine.llm_runner import JsonPromptRequest
from metis.engine.llm_runner import JsonPromptRunner
from metis.engine.nodes.simple_llm_review.graph import ReviewGraph
from metis.engine.nodes.simple_llm_review.graph import ReviewIncompleteError
from metis.engine.nodes.simple_llm_review.graph import _normalize_reviews
from metis.engine.nodes.simple_llm_review.graph import review_node_llm
from metis.engine.nodes.simple_llm_review.schema import ReviewResponseModel

FINDING = {"issue": "SQL injection", "code_snippet": "db.query(sql)"}


class _TextProvider:
    def __init__(self, *outcomes: str | Exception) -> None:
        self.calls = 0
        self._outcomes = outcomes

    def get_chat_model(self, **_params: Any) -> RunnableLambda:
        def respond(_messages: object) -> AIMessage:
            outcome = self._outcomes[min(self.calls, len(self._outcomes) - 1)]
            self.calls += 1
            if isinstance(outcome, Exception):
                raise outcome
            return AIMessage(content=outcome)

        return RunnableLambda(respond)


def _invoke(provider: _TextProvider, *, max_attempts: int = 2):
    runner = JsonPromptRunner(
        provider, max_attempts=max_attempts, retry_backoff_seconds=0
    )
    return runner.invoke(
        JsonPromptRequest(
            model="test-model",
            system_prompt="system",
            user_prompt="user",
            variables={},
            parse=_normalize_reviews,
            logger=logging.getLogger("metis.test.unusable_answers"),
            label="Review graph",
            batch_size=1,
            invalid_message="expected review JSON object",
            final_keep_message="no usable model answer for this chunk",
        )
    )


def test_bare_list_payload_is_parsed_into_findings():
    reviews = _normalize_reviews([FINDING])

    assert reviews is not None
    assert [review["issue"] for review in reviews] == ["SQL injection"]
    assert _normalize_reviews('[{"issue": "SQL injection"}]') is not None


@pytest.mark.parametrize(
    "raw",
    [None, "", "not json", '"just a string"', "42", {}, {"reviews": "none"}, 7],
)
def test_unusable_payload_is_not_a_clean_result(raw):
    assert _normalize_reviews(raw) is None


@pytest.mark.parametrize("raw", [{"reviews": []}, '{"reviews": []}', "[]", []])
def test_explicit_empty_payload_stays_clean(raw):
    assert _normalize_reviews(raw) == []


def test_runner_accepts_bare_array_answer_in_one_call():
    provider = _TextProvider(f"[{str(FINDING).replace(chr(39), chr(34))}]")

    reviews = _invoke(provider)

    assert reviews and reviews[0]["issue"] == "SQL injection"
    assert provider.calls == 1


def test_runner_retries_unparseable_answer_then_returns_none():
    provider = _TextProvider("I found nothing, sorry.")

    assert _invoke(provider, max_attempts=3) is None
    assert provider.calls == 3


def test_runner_treats_empty_reviews_object_as_success_without_retry():
    provider = _TextProvider('{"reviews": []}')

    assert _invoke(provider) == []
    assert provider.calls == 1


def test_runner_returns_none_when_every_model_call_errors():
    provider = _TextProvider(RuntimeError("Error code: 404 - model not found"))

    assert _invoke(provider) is None
    assert provider.calls == 2


def test_review_node_marks_missing_answer_incomplete():
    failed = review_node_llm({"snippet": "x"}, invoke_review=lambda *_args: None)
    clean = review_node_llm({"snippet": "x"}, invoke_review=lambda *_args: [])

    assert failed["review_incomplete"] is True
    assert clean["review_incomplete"] is False


def _review_graph(runner_result) -> ReviewGraph:
    provider = Mock()
    provider.count_tokens.side_effect = lambda text, **_: len(text)
    graph = ReviewGraph(provider, {}, None, "", "test-model", 4000)
    graph._prompt_runner.invoke = Mock(return_value=runner_result)
    return graph


_REQUEST = {
    "file_path": "users.ts",
    "snippet": "const a = 1;\n",
    "language_prompts": {
        "security_review_file": "Review. [[REVIEW_SCHEMA_FIELDS]]",
        "security_review_checks": "Check.",
    },
}


def test_review_graph_raises_when_no_usable_answer():
    with pytest.raises(ReviewIncompleteError, match="users.ts"):
        _review_graph(None).review(_REQUEST)


def test_review_graph_reports_clean_file_for_explicit_empty_answer():
    result = _review_graph([]).review(_REQUEST)

    assert result["reviews"] == []


class _StructuredTextProvider:
    """Structured-output chat model that answers in text, not with the schema tool."""

    def __init__(self, text: str) -> None:
        self.calls = 0
        self._text = text

    def get_chat_model(self, **_params: Any) -> RunnableLambda:
        def respond(_messages: object) -> dict[str, object | None]:
            self.calls += 1
            return {
                "raw": AIMessage(content=self._text),
                "parsed": None,
                "parsing_error": None,
            }

        chat = RunnableLambda(lambda _messages: AIMessage(content="unused"))
        setattr(
            chat,
            "with_structured_output",
            lambda *_args, **_kwargs: RunnableLambda(respond),
        )
        return chat


@pytest.mark.parametrize(
    ("text", "expected_calls", "expected"),
    [
        ('[{"issue": "SQL injection"}]', 1, "SQL injection"),
        ('{"reviews": []}', 1, None),
        ("no schema call and no JSON", 2, "unusable"),
    ],
)
def test_structured_output_without_schema_call_uses_the_text(
    text, expected_calls, expected
):
    provider = _StructuredTextProvider(text)
    runner = JsonPromptRunner(provider, max_attempts=2, retry_backoff_seconds=0)

    reviews = runner.invoke(
        JsonPromptRequest(
            model="test-model",
            system_prompt="system",
            user_prompt="user",
            variables={},
            parse=_normalize_reviews,
            logger=logging.getLogger("metis.test.unusable_answers"),
            label="Review graph",
            batch_size=1,
            invalid_message="expected review JSON object",
            final_keep_message="no usable model answer for this chunk",
            response_model=ReviewResponseModel,
        )
    )

    assert provider.calls == expected_calls
    if expected == "unusable":
        assert reviews is None
    elif expected is None:
        assert reviews == []
    else:
        assert reviews and reviews[0]["issue"] == expected
