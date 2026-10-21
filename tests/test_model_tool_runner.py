# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import json

import pytest
from langchain_core.messages import AIMessage
from langchain_core.prompts import ChatPromptTemplate

from metis.engine.model_tool_runner import ModelToolConfigurationError
from metis.engine.model_tool_runner import ModelOutputLimitError
from metis.engine.model_tool_runner import ModelInputLimitError
from metis.engine.model_tool_runner import model_messages_token_count
from metis.engine.model_tool_runner import invoke_model_with_tools
from metis.engine.model_tool_runner import model_tool_system_prompt
from metis.engine.model_tool_runner import require_max_tool_rounds


class _FakeTool:
    name = "index_search"
    description = "Search indexed context."

    def __init__(self):
        self.calls = []
        self.metadata = {
            "metis_contract": (
                "CONTRACT TEXT\nUse index_search for missing project context."
            )
        }

    def invoke(self, args):
        self.calls.append(args)
        return "indexed context"


class _FakeToolChat:
    def __init__(self):
        self.messages = []

    def invoke(self, messages):
        self.messages.append(list(messages))
        if len(self.messages) == 1:
            return AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "call-1",
                        "name": "index_search",
                        "args": {"query": "allocator ownership"},
                    }
                ],
            )
        return AIMessage(content='{"reviews": []}')


class _FakeChat:
    def __init__(self):
        self.bound_chat = _FakeToolChat()
        self.bound_tools = None
        self.messages = []

    def bind_tools(self, tools):
        self.bound_tools = list(tools)
        return self.bound_chat

    def invoke(self, messages):
        self.messages.append(list(messages))
        return AIMessage(content='{"reviews": []}')


def _prompt():
    return ChatPromptTemplate.from_messages(
        [
            ("system", "Return JSON."),
            ("user", "{body}"),
        ]
    )


def test_model_tool_system_prompt_includes_and_clips_tool_contracts():
    long_contract_tool = _FakeTool()
    long_contract_tool.metadata = {
        "metis_contract": "0123456789abcdef",
        "metis_contract_max_chars": 6,
    }
    prompt = model_tool_system_prompt("Return JSON.", (_FakeTool(), long_contract_tool))

    assert "AVAILABLE MODEL TOOLS" in prompt
    assert "- index_search: Search indexed context." in prompt
    assert "MODEL TOOL CONTRACTS" in prompt
    assert "CONTRACT TEXT" in prompt
    assert "012345\n[contract truncated]" in prompt


def test_invoke_model_with_tools_executes_tool_calls_and_logs_debug(caplog):
    tool = _FakeTool()
    chat = _FakeChat()
    caplog.set_level(logging.DEBUG, logger="metis")

    result, evidence = invoke_model_with_tools(
        chat,
        _prompt(),
        {"body": "review this"},
        (tool,),
        max_tool_rounds=2,
    )

    assert result == '{"reviews": []}'
    assert evidence == (
        (
            "Tool: index_search\n"
            'Arguments: {"query": "allocator ownership"}\n'
            "Status: success\n"
            "Output:\nindexed context"
        ),
    )
    assert chat.bound_tools == [tool]
    assert tool.calls == [{"query": "allocator ownership"}]
    messages = [record.getMessage() for record in caplog.records]
    assert any(
        "Invoking model tool index_search with args={'query': 'allocator ownership'}"
        in message
        for message in messages
    )
    assert any(
        "Model tool index_search completed with 15 output chars" in message
        for message in messages
    )


def test_invoke_model_with_tools_requests_final_answer_after_last_tool_round():
    tool = _FakeTool()
    chat = _FakeChat()

    result, evidence = invoke_model_with_tools(
        chat,
        _prompt(),
        {"body": "review this"},
        (tool,),
        max_tool_rounds=1,
    )

    assert result == '{"reviews": []}'
    assert evidence
    assert tool.calls == [{"query": "allocator ownership"}]


def test_require_max_tool_rounds_rejects_missing_value():
    with pytest.raises(
        ModelToolConfigurationError,
        match="max_tool_rounds must be configured when model_tools are used",
    ):
        require_max_tool_rounds(None)


def test_truncated_tool_request_is_rejected_before_execution():
    tool = _FakeTool()
    chat = _FakeChat()
    chat.bound_chat.invoke = lambda _messages: AIMessage(
        content="",
        response_metadata={
            "status": "incomplete",
            "incomplete_details": {"reason": "max_output_tokens"},
        },
        tool_calls=[
            {"name": tool.name, "id": "partial", "args": {"query": "allocator"}}
        ],
    )
    with pytest.raises(ModelOutputLimitError):
        invoke_model_with_tools(
            chat, _prompt(), {"body": "review"}, (tool,), max_tool_rounds=1
        )
    assert tool.calls == []


def test_identical_navigation_contracts_are_included_once():
    first = _FakeTool()
    second = _FakeTool()
    second.name = "sed"
    prompt = model_tool_system_prompt("Review.", (first, second))
    assert prompt.count(first.metadata["metis_contract"]) == 1
    assert "[index_search, sed]" in prompt


@pytest.mark.parametrize("max_tool_rounds", [1, 2])
def test_input_limit_stops_tool_history_before_the_next_model_call(max_tool_rounds):
    tool = _FakeTool()
    chat = _FakeChat()
    with pytest.raises(ModelInputLimitError, match="max_input_tokens=64"):
        invoke_model_with_tools(
            chat,
            _prompt(),
            {"body": "review this"},
            (tool,),
            max_tool_rounds=max_tool_rounds,
            token_counter=len,
            max_input_tokens=64,
        )
    assert len(tool.calls) == 1
    assert len(chat.bound_chat.messages) == 1
    assert chat.messages == []


@pytest.mark.parametrize(
    ("block_type", "id_key"),
    [("function_call", "call_id"), ("tool_use", "id"), ("tool_call", "id")],
)
def test_input_count_does_not_double_count_tool_calls(block_type, id_key):
    call = {"id": "call-1", "name": "lookup", "args": {"query": "guard"}}
    message = AIMessage(
        content=[{"type": block_type, id_key: call["id"]}], tool_calls=[call]
    )
    assert model_messages_token_count([message], len) == len(str(message.content))
    message.tool_calls.append({**message.tool_calls[0], "id": "call-2"})
    assert model_messages_token_count([message], len) == len(
        str(message.content)
    ) + len(json.dumps(message.tool_calls[1:], sort_keys=True))
