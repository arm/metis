# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging

import pytest
from langchain_core.messages import AIMessage
from langchain_core.messages import ToolMessage

from metis.engine.llm_runner import JsonPromptRequest
from metis.engine.llm_runner import JsonPromptRunner
from metis.engine.llm_runner import ModelToolConfigurationError


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


class _FakeProvider:
    def __init__(self, chat):
        self.chat = chat

    def get_chat_model(self, **_params):
        return self.chat


class _FakeNoToolChat:
    pass


def test_json_prompt_runner_executes_model_tool_calls_before_parsing():
    tool = _FakeTool()
    chat = _FakeChat()
    runner = JsonPromptRunner(_FakeProvider(chat))

    result = runner.invoke(
        JsonPromptRequest(
            model="test-model",
            system_prompt="Return JSON.",
            user_prompt="{body}",
            variables={"body": "review this"},
            parse=lambda text: text,
            logger=logging.getLogger("test"),
            label="test",
            batch_size=1,
            invalid_message="invalid",
            final_keep_message="done",
            model_tools=(tool,),
            max_tool_rounds=2,
        )
    )

    assert result == '{"reviews": []}'
    assert chat.bound_tools == [tool]
    assert tool.calls == [{"query": "allocator ownership"}]
    assert any(
        isinstance(message, ToolMessage) for message in chat.bound_chat.messages[1]
    )
    system_prompt = chat.bound_chat.messages[0][0].content
    assert "AVAILABLE MODEL TOOLS" in system_prompt
    assert "MODEL TOOL CONTRACTS" in system_prompt
    assert "CONTRACT TEXT" in system_prompt


def test_json_prompt_runner_requires_configured_model_tool_rounds():
    tool = _FakeTool()
    chat = _FakeChat()
    runner = JsonPromptRunner(_FakeProvider(chat))

    with pytest.raises(
        ModelToolConfigurationError,
        match="max_tool_rounds must be configured when model_tools are used",
    ):
        runner.invoke(
            JsonPromptRequest(
                model="test-model",
                system_prompt="Return JSON.",
                user_prompt="{body}",
                variables={"body": "review this"},
                parse=lambda text: text,
                logger=logging.getLogger("test"),
                label="test",
                batch_size=1,
                invalid_message="invalid",
                final_keep_message="done",
                model_tools=(tool,),
            )
        )

    assert chat.bound_tools is None
    assert tool.calls == []


def test_json_prompt_runner_requires_bind_tools_support_for_model_tools():
    tool = _FakeTool()
    runner = JsonPromptRunner(_FakeProvider(_FakeNoToolChat()))

    with pytest.raises(
        ModelToolConfigurationError,
        match="model_tools require a LangChain chat model with bind_tools support",
    ):
        runner.invoke(
            JsonPromptRequest(
                model="test-model",
                system_prompt="Return JSON.",
                user_prompt="{body}",
                variables={"body": "review this"},
                parse=lambda text: text,
                logger=logging.getLogger("test"),
                label="test",
                batch_size=1,
                invalid_message="invalid",
                final_keep_message="done",
                model_tools=(tool,),
                max_tool_rounds=1,
            )
        )

    assert tool.calls == []
