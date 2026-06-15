# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging

import pytest
from langchain_core.messages import AIMessage
from langchain_core.prompts import ChatPromptTemplate

from metis.engine.model_tool_runner import ModelToolConfigurationError
from metis.engine.model_tool_runner import invoke_model_with_tools
from metis.engine.model_tool_runner import model_tool_system_prompt
from metis.engine.model_tool_runner import require_max_tool_rounds


class _FakeTool:
    name = "index_search"
    description = "Search indexed context."
    metadata = {
        "metis_contract": "CONTRACT TEXT\nUse index_search for missing project context."
    }

    def __init__(self):
        self.calls = []

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

    def bind_tools(self, tools):
        self.bound_tools = list(tools)
        return self.bound_chat


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

    result = invoke_model_with_tools(
        chat,
        _prompt(),
        {"body": "review this"},
        (tool,),
        max_tool_rounds=2,
    )

    assert result == '{"reviews": []}'
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

    result = invoke_model_with_tools(
        chat,
        _prompt(),
        {"body": "review this"},
        (tool,),
        max_tool_rounds=1,
    )

    assert result == '{"reviews": []}'
    assert tool.calls == [{"query": "allocator ownership"}]
    assert len(chat.bound_chat.messages) == 2


def test_require_max_tool_rounds_rejects_missing_value():
    with pytest.raises(
        ModelToolConfigurationError,
        match="max_tool_rounds must be configured when model_tools are used",
    ):
        require_max_tool_rounds(None)
