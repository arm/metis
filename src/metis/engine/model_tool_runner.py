# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Any

from langchain_core.messages import ToolMessage
from langchain_core.prompts import ChatPromptTemplate

logger = logging.getLogger("metis")


class ModelToolConfigurationError(ValueError):
    """Raised when model tools are enabled without required runtime support."""


def require_max_tool_rounds(value: int | None) -> int:
    if value is None:
        raise ModelToolConfigurationError(
            "max_tool_rounds must be configured when model_tools are used"
        )
    try:
        max_tool_rounds = int(value)
    except (TypeError, ValueError) as exc:
        raise ModelToolConfigurationError(
            "max_tool_rounds must be a positive integer"
        ) from exc
    if max_tool_rounds <= 0:
        raise ModelToolConfigurationError("max_tool_rounds must be a positive integer")
    return max_tool_rounds


def model_tool_system_prompt(system_prompt: str, tools: tuple[Any, ...]) -> str:
    if not tools:
        return system_prompt
    lines = [
        system_prompt.rstrip(),
        "",
        "AVAILABLE MODEL TOOLS",
        "Use these tools only when they can provide missing project context. "
        "After any tool calls, return the final response in the requested format.",
    ]
    for tool in tools:
        name = getattr(tool, "name", "")
        description = getattr(tool, "description", "")
        if name and description:
            lines.append(f"- {name}: {description}")
        elif name:
            lines.append(f"- {name}")
    contract_sections = _tool_contract_sections(tools)
    if contract_sections:
        lines.extend(["", "MODEL TOOL CONTRACTS", *contract_sections])
    return "\n".join(lines).strip()


def invoke_model_with_tools(
    chat,
    prompt: ChatPromptTemplate,
    variables: dict[str, Any],
    tools: tuple[Any, ...],
    *,
    max_tool_rounds: int,
) -> str:
    bind_tools = getattr(chat, "bind_tools", None)
    if not callable(bind_tools):
        raise ModelToolConfigurationError(
            "model_tools require a LangChain chat model with bind_tools support"
        )

    tool_chat = bind_tools(list(tools))
    tool_by_name = {getattr(tool, "name", ""): tool for tool in tools}
    messages = prompt.invoke(variables).to_messages()
    last_response = None
    for _ in range(max_tool_rounds):
        last_response = tool_chat.invoke(messages)
        tool_calls = list(getattr(last_response, "tool_calls", None) or [])
        if not tool_calls:
            return _message_content_text(last_response)
        messages.append(last_response)
        for index, tool_call in enumerate(tool_calls):
            name = str(tool_call.get("name") or "")
            args = tool_call.get("args") or {}
            tool_call_id = str(tool_call.get("id") or f"{name}-{index}")
            status = "success"
            try:
                tool = tool_by_name[name]
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "Invoking model tool %s with args=%s",
                        name,
                        _debug_tool_args(args),
                    )
                content = tool.invoke(args)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "Model tool %s completed with %d output chars",
                        name,
                        len(str(content)),
                    )
            except Exception as exc:
                status = "error"
                content = f"Tool {name!r} failed: {exc}"
                logger.debug("Model tool %s failed: %s", name, exc)
            messages.append(
                ToolMessage(
                    content=str(content),
                    name=name,
                    tool_call_id=tool_call_id,
                    status=status,
                )
            )
    last_response = tool_chat.invoke(messages)
    return _message_content_text(last_response)


def _tool_contract_sections(tools: tuple[Any, ...]) -> list[str]:
    sections = []
    for tool in tools:
        metadata = getattr(tool, "metadata", None) or {}
        if not isinstance(metadata, dict):
            continue
        contract = _clip_tool_contract(
            str(metadata.get("metis_contract") or ""),
            metadata.get("metis_contract_max_chars"),
        )
        if not contract:
            continue
        name = getattr(tool, "name", "tool")
        sections.append(f"[{name}]\n{contract}")
    return sections


def _clip_tool_contract(contract: str, max_chars: Any) -> str:
    text = contract.strip()
    limit = _positive_int(max_chars)
    if limit is None or len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n[contract truncated]"


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    return parsed


def _debug_tool_args(args: Any) -> Any:
    if not isinstance(args, dict):
        return args
    clipped = {}
    for key, value in args.items():
        if isinstance(value, str) and len(value) > 300:
            clipped[key] = value[:300] + "...[truncated]"
        else:
            clipped[key] = value
    return clipped


def _message_content_text(message: Any) -> str:
    content = getattr(message, "content", message)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and item.get("text") is not None:
                parts.append(str(item["text"]))
        return "\n".join(parts)
    return str(content or "")
