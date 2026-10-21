# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import CancelledError
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.messages import ToolMessage
from langchain_core.runnables import RunnableLambda

from metis.cli.entry import run_non_interactive
from metis.cli import entry
from metis.engine import MetisEngine
from metis.engine.model_tool_runner import ModelOutputLimitError


class _ReviewProvider:
    def __init__(self, response):
        self.response = response
        self.calls = []
        self.tools = []

    def count_tokens(self, text):
        return len(text)

    def get_chat_model(self, **_params):
        def respond(messages):
            if hasattr(messages, "to_messages"):
                messages = messages.to_messages()
            self.calls.append(list(messages))
            if isinstance(self.response, Exception):
                raise self.response
            if self.response == "navigate" and len(self.calls) == 1:
                return AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "sed",
                            "id": "read-header",
                            "args": {
                                "path": "limits.h",
                                "start_line": 1,
                                "end_line": 3,
                            },
                        }
                    ],
                )
            return (
                self.response
                if isinstance(self.response, AIMessage)
                else AIMessage(content='{"reviews": []}')
            )

        chat = RunnableLambda(respond)

        def bind_tools(tools):
            self.tools = [tool.name for tool in tools]
            return chat

        chat.bind_tools = bind_tools
        return chat


@pytest.fixture
def c_engine(tmp_path, dummy_backend):
    (tmp_path / "main.c").write_text(
        '#include "limits.h"\nint main(void) { return CAPACITY; }\n', encoding="utf-8"
    )
    (tmp_path / "limits.h").write_text("#define CAPACITY 8\n", encoding="utf-8")
    provider = _ReviewProvider("navigate")
    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=provider,
        max_workers=2,
        max_token_length=32000,
        llama_query_model="gpt-test",
        similarity_top_k=5,
    )
    engine.reachability.review_file = Mock(
        side_effect=AssertionError("reachability ran")
    )
    engine.reachability.review_codebase = Mock(
        side_effect=AssertionError("reachability ran")
    )
    yield engine, provider, tmp_path / "main.c"
    engine.close()


def test_c_review_uses_simple_prompt_and_real_navigation(c_engine):
    engine, provider, source = c_engine
    result = engine.review.review_file(str(source))
    assert result["reviews"] == []
    assert provider.tools == ["grep", "find_name", "cat", "sed"]
    assert len(provider.calls) == 2
    assert (
        "Review security failures in the assigned FILE" in provider.calls[0][0].content
    )
    evidence = [
        message for message in provider.calls[1] if isinstance(message, ToolMessage)
    ]
    assert evidence[0].content == "1: #define CAPACITY 8"
    engine.reachability.review_file.assert_not_called()
    engine.reachability.review_codebase.assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("Unsupported parameter: temperature"),
        AIMessage(content="not-json"),
        AIMessage(
            content='{"reviews": []}', response_metadata={"finish_reason": "length"}
        ),
    ],
)
def test_c_review_failure_does_not_become_success(c_engine, monkeypatch, failure):
    engine, provider, source = c_engine
    monkeypatch.setattr("metis.engine.llm_runner.time.sleep", lambda _seconds: None)
    provider.response = failure
    with pytest.raises((RuntimeError, ModelOutputLimitError)):
        engine.review.review_file(str(source))
    assert len(provider.calls) == 2


def test_bulk_review_propagates_failure_after_draining(c_engine, monkeypatch):
    engine, provider, source = c_engine
    monkeypatch.setattr("metis.engine.llm_runner.time.sleep", lambda _seconds: None)
    provider.response = RuntimeError("model unavailable")
    with pytest.raises(RuntimeError, match="Review failed for 1 file"):
        list(engine.review.review_code(get_code_files_func=lambda: [str(source)]))


def test_cancelled_c_review_is_not_retried(c_engine):
    engine, provider, source = c_engine
    provider.response = CancelledError()
    with pytest.raises(CancelledError):
        engine.review.review_file(str(source))
    assert len(provider.calls) == 1


def test_failed_c_review_exits_nonzero_without_a_clean_report(
    c_engine, monkeypatch, capsys
):
    engine, provider, source = c_engine
    monkeypatch.setattr("metis.engine.llm_runner.time.sleep", lambda _seconds: None)
    provider.response = RuntimeError("Unsupported parameter: temperature")
    report = source.parent / "failed.json"
    args = SimpleNamespace(
        verbose=True,
        quiet=False,
        command=f"review_file {source}",
        output_file=[str(report)],
        tools=None,
        triage=False,
    )
    status, _farewell = run_non_interactive(engine, args)
    assert status == 1
    assert not report.exists()
    assert "No issues" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "command",
    ["review_file main.c", "review_dir .", "review_code", "review_patch change.diff"],
)
@pytest.mark.parametrize("explicit_config", [False, True])
def test_review_commands_keep_existing_cli_and_outputs(
    c_engine, dummy_backend, monkeypatch, command, explicit_config
):
    _engine, provider, source = c_engine
    workdir = source.parent
    monkeypatch.chdir(workdir)
    config = workdir / "metis.yaml"
    config.write_text(
        "metis_engine:\n  max_workers: 1\n  max_token_length: 32000\n"
        "llm_provider:\n  name: openai\n  model: gpt-test\n  api_key: offline-test-key\n"
        "query:\n  max_tokens: 64000\n  temperature: null\n",
        encoding="utf-8",
    )
    (workdir / "change.diff").write_text(
        "--- a/main.c\n+++ b/main.c\n@@ -1,2 +1,2 @@\n"
        ' #include "limits.h"\n'
        "-int main(void) { return CAPACITY; }\n"
        "+int main(void) { return CAPACITY - 1; }\n",
        encoding="utf-8",
    )
    json_report = workdir / "review.json"
    sarif_report = workdir / "review.sarif"
    arguments = [
        "metis",
        "--non-interactive",
        "--command",
        command,
        "--codebase-path",
        str(workdir),
        "--verbose",
        "--log-level",
        "DEBUG",
        "--output-file",
        str(json_report),
        "--output-file",
        str(sarif_report),
    ]
    if explicit_config:
        arguments.extend(["--config", str(config)])
    monkeypatch.setattr(sys, "argv", arguments)
    monkeypatch.setattr(
        entry, "get_chat_provider", lambda _name: lambda _config: provider
    )
    monkeypatch.setattr(entry, "build_chroma_backend", lambda *_args: dummy_backend)
    monkeypatch.setattr(entry, "configure_logger", lambda *_args: None)

    entry.main()

    assert provider.calls
    assert provider.tools == ["grep", "find_name", "cat", "sed"]
    output = json.loads(json_report.read_text(encoding="utf-8"))
    assert isinstance(output["reviews"], list)
    assert output["reviews"]
    assert all(isinstance(group["reviews"], list) for group in output["reviews"])
    assert json.loads(sarif_report.read_text(encoding="utf-8"))["version"] == "2.1.0"
    if command.startswith("review_patch"):
        body = provider.calls[0][-1].content
        assert "FILE_CHANGES:\n--- a/main.c\n+++ b/main.c\n@@ -1,2 +1,2 @@" in body
        assert ' #include "limits.h"' in body
