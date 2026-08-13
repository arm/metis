import logging
from collections.abc import Callable
from typing import Any

import pytest
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda

from metis.engine.llm_runner import (
    JsonPromptRequest,
    JsonPromptRunner,
    rendered_prompt_token_count,
)


class _CountingProvider:
    def __init__(self, responses: list[AIMessage] | None = None) -> None:
        self.calls = 0
        self._responses = responses or [AIMessage(content="not-json")]

    def get_chat_model(self, **_params: Any) -> RunnableLambda:
        def _respond(_messages: object) -> AIMessage:
            response = self._responses[min(self.calls, len(self._responses) - 1)]
            self.calls += 1
            return response

        return RunnableLambda(_respond)


class _StructuredProvider:
    def __init__(
        self,
        responses: list[object],
        raw_responses: list[AIMessage] | None = None,
    ) -> None:
        self.raw_calls = 0
        self.structured_calls = 0
        self._responses = responses
        self._raw_responses = raw_responses or [AIMessage(content="")]

    def get_chat_model(self, **_params: Any) -> RunnableLambda:
        def _respond_raw(_messages: object) -> AIMessage:
            self.raw_calls += 1
            return AIMessage(content='{"ok": true}')

        def _respond_structured(_messages: object) -> dict[str, object | None]:
            index = min(self.structured_calls, len(self._responses) - 1)
            response = self._responses[index]
            raw_response = self._raw_responses[min(index, len(self._raw_responses) - 1)]
            self.structured_calls += 1
            return {
                "raw": raw_response,
                "parsed": response,
                "parsing_error": None,
            }

        chat = RunnableLambda(_respond_raw)
        setattr(
            chat,
            "with_structured_output",
            lambda *_args, **_kwargs: RunnableLambda(_respond_structured),
        )
        return chat


def _request(
    logger: logging.Logger,
    *,
    parse: Callable[[Any], Any] | None = None,
    on_output_limit: Callable[[], None] | None = None,
    response_model: type | None = None,
) -> JsonPromptRequest:
    return JsonPromptRequest(
        model="test-model",
        system_prompt="system",
        user_prompt="user {x}",
        variables={"x": "v"},
        parse=parse or (lambda _raw: None),
        logger=logger,
        label="Test prompt",
        batch_size=3,
        invalid_message="bad payload",
        final_keep_message="giving up",
        on_output_limit=on_output_limit,
        response_model=response_model,
    )


def test_retries_configured_attempts_with_backoff(monkeypatch, caplog):
    sleeps = []
    monkeypatch.setattr("metis.engine.llm_runner.time.sleep", sleeps.append)
    provider = _CountingProvider()
    logger = logging.getLogger("metis.test.retry")

    with caplog.at_level(logging.WARNING, logger="metis.test.retry"):
        result = JsonPromptRunner(
            provider, max_attempts=4, retry_backoff_seconds=0.5
        ).invoke(_request(logger))

    assert result is None
    assert provider.calls == 4
    assert sleeps == [0.5, 1.0, 2.0]
    assert "retrying (attempt 1/4)" in caplog.text
    assert "retrying (attempt 3/4)" in caplog.text
    assert "giving up" in caplog.text


def test_zero_backoff_skips_sleep(monkeypatch):
    monkeypatch.setattr(
        "metis.engine.llm_runner.time.sleep",
        lambda _s: (_ for _ in ()).throw(AssertionError("should not sleep")),
    )
    logger = logging.getLogger("metis.test.retry.zero")

    result = JsonPromptRunner(
        _CountingProvider(), max_attempts=2, retry_backoff_seconds=0
    ).invoke(_request(logger))

    assert result is None


def test_structured_validation_retry_does_not_fall_back_to_unstructured_text():
    provider = _StructuredProvider([{"ok": False}, {"ok": True}])
    request = _request(
        logging.getLogger("metis.test.retry.structured"),
        parse=lambda raw: raw if raw == {"ok": True} else None,
        response_model=dict,
    )

    result = JsonPromptRunner(
        provider,
        max_attempts=2,
        retry_backoff_seconds=0,
    ).invoke(request)

    assert result == {"ok": True}
    assert provider.structured_calls == 2
    assert provider.raw_calls == 0


@pytest.mark.parametrize(
    ("metadata_field", "metadata"),
    [
        ("response_metadata", {"finish_reason": "length"}),
        (
            "response_metadata",
            {
                "status": "incomplete",
                "incomplete_details": {"reason": "max_output_tokens"},
            },
        ),
        ("additional_kwargs", {"stop_reason": "max_tokens"}),
    ],
)
def test_output_limit_callback_runs_once_after_all_attempts_fail(
    metadata_field: str,
    metadata: dict[str, object],
) -> None:
    callbacks: list[str] = []
    provider = _CountingProvider(
        [AIMessage(content="not-json", **{metadata_field: metadata})]
    )

    result = JsonPromptRunner(
        provider,
        max_attempts=2,
        retry_backoff_seconds=0,
    ).invoke(
        _request(
            logging.getLogger("metis.test.retry.output-limit"),
            on_output_limit=lambda: callbacks.append("output-limit"),
        )
    )

    assert result is None
    assert provider.calls == 2
    assert callbacks == ["output-limit"]


@pytest.mark.parametrize(
    ("metadata_field", "metadata"),
    [
        ("response_metadata", {"finish_reason": "stop"}),
        (
            "response_metadata",
            {
                "status": "incomplete",
                "incomplete_details": {"reason": "content_filter"},
            },
        ),
        ("additional_kwargs", {"stop_reason": "end_turn"}),
    ],
)
def test_non_limit_stop_does_not_trigger_callback(
    metadata_field: str,
    metadata: dict[str, object],
) -> None:
    callbacks: list[str] = []
    provider = _CountingProvider(
        [AIMessage(content="not-json", **{metadata_field: metadata})]
    )

    result = JsonPromptRunner(
        provider,
        max_attempts=1,
        retry_backoff_seconds=0,
    ).invoke(
        _request(
            logging.getLogger("metis.test.retry.not-output-limit"),
            on_output_limit=lambda: callbacks.append("output-limit"),
        )
    )

    assert result is None
    assert provider.calls == 1
    assert callbacks == []


def test_valid_response_with_limit_metadata_does_not_trigger_callback() -> None:
    callbacks: list[str] = []
    provider = _CountingProvider(
        [
            AIMessage(
                content='{"ok": true}',
                response_metadata={"finish_reason": "length"},
            )
        ]
    )

    result = JsonPromptRunner(
        provider,
        max_attempts=1,
        retry_backoff_seconds=0,
    ).invoke(
        _request(
            logging.getLogger("metis.test.retry.valid-output-limit"),
            parse=lambda raw: {"ok": True} if raw == '{"ok": true}' else None,
            on_output_limit=lambda: callbacks.append("output-limit"),
        )
    )

    assert result == {"ok": True}
    assert provider.calls == 1
    assert callbacks == []


def test_successful_retry_suppresses_prior_output_limit_callback() -> None:
    callbacks: list[str] = []
    provider = _CountingProvider(
        [
            AIMessage(
                content="not-json",
                additional_kwargs={"stopReason": "MAX_TOKENS"},
            ),
            AIMessage(content='{"ok": true}'),
        ]
    )

    result = JsonPromptRunner(
        provider,
        max_attempts=2,
        retry_backoff_seconds=0,
    ).invoke(
        _request(
            logging.getLogger("metis.test.retry.success-after-output-limit"),
            parse=lambda raw: {"ok": True} if raw == '{"ok": true}' else None,
            on_output_limit=lambda: callbacks.append("output-limit"),
        )
    )

    assert result == {"ok": True}
    assert provider.calls == 2
    assert callbacks == []


def test_rendered_prompt_token_count_uses_chat_prompt_rendering():
    tokens = rendered_prompt_token_count(
        len,
        system_prompt="system {literal}",
        user_prompt="value {value} and {{escaped}}",
        variables={"value": "replacement"},
    )

    assert tokens == len("system {literal}") + len("value replacement and {escaped}")
