import logging

from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda

from metis.engine.llm_runner import JsonPromptRequest, JsonPromptRunner


class _CountingProvider:
    def __init__(self):
        self.calls = 0

    def get_chat_model(self, **_params):
        def _respond(_messages):
            self.calls += 1
            return AIMessage(content="not-json")

        return RunnableLambda(_respond)


def _request(logger):
    return JsonPromptRequest(
        model="test-model",
        system_prompt="system",
        user_prompt="user {x}",
        variables={"x": "v"},
        parse=lambda _raw: None,
        logger=logger,
        label="Test prompt",
        batch_size=3,
        invalid_message="bad payload",
        final_keep_message="giving up",
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
