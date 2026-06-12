# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging

import pytest
from langchain_core.messages import AIMessage
from langchain_core.messages import ToolMessage
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


class _LongContractTool(_FakeTool):
    metadata = {
        "metis_contract": "0123456789abcdef",
        "metis_contract_max_chars": 6,
    }


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


class _FakeNoToolChat:
    pass


def test_model_tool_system_prompt_includes_tool_contract():
    prompt = model_tool_system_prompt("Return JSON.", (_FakeTool(),))

    assert "AVAILABLE MODEL TOOLS" in prompt
    assert "- index_search: Search indexed context." in prompt
    assert "MODEL TOOL CONTRACTS" in prompt
    assert "CONTRACT TEXT" in prompt


def test_model_tool_system_prompt_clips_contract_from_tool_metadata():
    prompt = model_tool_system_prompt("Return JSON.", (_LongContractTool(),))

    assert "012345\n[contract truncated]" in prompt
    assert "0123456789abcdef" not in prompt


def test_invoke_model_with_tools_executes_tool_calls():
    tool = _FakeTool()
    chat = _FakeChat()
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", model_tool_system_prompt("Return JSON.", (tool,))),
            ("user", "{body}"),
        ]
    )

    result = invoke_model_with_tools(
        chat,
        prompt,
        {"body": "review this"},
        (tool,),
        max_tool_rounds=2,
    )

    assert result == '{"reviews": []}'
    assert chat.bound_tools == [tool]
    assert tool.calls == [{"query": "allocator ownership"}]
    assert any(
        isinstance(message, ToolMessage) for message in chat.bound_chat.messages[1]
    )


def test_invoke_model_with_tools_logs_debug_invocations(caplog):
    tool = _FakeTool()
    chat = _FakeChat()
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", "Return JSON."),
            ("user", "{body}"),
        ]
    )
    caplog.set_level(logging.DEBUG, logger="metis")

    invoke_model_with_tools(
        chat,
        prompt,
        {"body": "review this"},
        (tool,),
        max_tool_rounds=2,
    )

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


def test_invoke_model_with_tools_skips_debug_logs_at_info(caplog):
    tool = _FakeTool()
    chat = _FakeChat()
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", "Return JSON."),
            ("user", "{body}"),
        ]
    )
    caplog.set_level(logging.INFO, logger="metis")

    invoke_model_with_tools(
        chat,
        prompt,
        {"body": "review this"},
        (tool,),
        max_tool_rounds=2,
    )

    assert not any(
        "model tool" in record.getMessage().lower() for record in caplog.records
    )


def test_require_max_tool_rounds_rejects_missing_value():
    with pytest.raises(
        ModelToolConfigurationError,
        match="max_tool_rounds must be configured when model_tools are used",
    ):
        require_max_tool_rounds(None)


def test_invoke_model_with_tools_requires_bind_tools_support():
    tool = _FakeTool()
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", "Return JSON."),
            ("user", "{body}"),
        ]
    )

    with pytest.raises(
        ModelToolConfigurationError,
        match="model_tools require a LangChain chat model with bind_tools support",
    ):
        invoke_model_with_tools(
            _FakeNoToolChat(),
            prompt,
            {"body": "review this"},
            (tool,),
            max_tool_rounds=1,
        )

    assert tool.calls == []
