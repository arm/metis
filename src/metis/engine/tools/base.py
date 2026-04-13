# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


ToolInvoke = Callable[..., Any]


@dataclass(frozen=True, slots=True)
class ToolContext:
    codebase_path: str
    timeout_seconds: int = 8
    max_chars: int = 16000


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    domains: tuple[str, ...]
    provider: str
    operation: str


class ToolBox:
    def __init__(self, tools: dict[str, ToolInvoke]):
        self._tools = dict(tools)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def list_tools(self) -> tuple[str, ...]:
        return self.names

    def has(self, name: str) -> bool:
        return name in self._tools

    def without(self, *names: str) -> "ToolBox":
        blocked = set(names)
        return ToolBox(
            {name: tool for name, tool in self._tools.items() if name not in blocked}
        )

    def run(self, name: str, *args, **kwargs):
        try:
            tool = self._tools[name]
        except KeyError as exc:
            raise ValueError(f"Unknown tool: {name}") from exc
        return tool(*args, **kwargs)

    def describe(self, name: str) -> dict[str, Any]:
        try:
            tool = self._tools[name]
        except KeyError as exc:
            raise ValueError(f"Unknown tool: {name}") from exc
        provider = getattr(tool, "__self__", None)
        if provider is None:
            return {}
        describe_tool = getattr(provider, "describe_tool", None)
        if not callable(describe_tool):
            return {}
        details = describe_tool(name)
        if not isinstance(details, dict):
            return {}
        return dict(details)

    def describe_call(self, name: str, *args, **kwargs) -> dict[str, Any]:
        try:
            tool = self._tools[name]
        except KeyError as exc:
            raise ValueError(f"Unknown tool: {name}") from exc
        provider = getattr(tool, "__self__", None)
        if provider is None:
            return self.describe(name)
        describe_call = getattr(provider, "describe_call", None)
        if callable(describe_call):
            details = describe_call(name, *args, **kwargs)
            if isinstance(details, dict):
                return dict(details)
        return self.describe(name)

    def grep(self, pattern: str, path: str) -> str:
        return self.run("grep", pattern, path)

    def find_name(self, name: str, max_results: int = 20) -> list[str]:
        return self.run("find_name", name, max_results=max_results)

    def cat(self, path: str) -> str:
        return self.run("cat", path)

    def sed(self, path: str, start_line: int, end_line: int) -> str:
        return self.run("sed", path, start_line, end_line)

    def rag_search(
        self,
        query: str,
        *,
        retriever_code=None,
        retriever_docs=None,
    ) -> str:
        return self.run(
            "rag_search",
            query,
            retriever_code=retriever_code,
            retriever_docs=retriever_docs,
        )
