# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Any, Callable

from langchain_core.messages import SystemMessage
from langchain_core.messages import ToolMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.chat_model_options import merge_chat_model_kwargs

_MAX_TOOL_CONTRACT_CHARS = 6000


class ModelToolConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class JsonPromptRequest:
    model: str
    system_prompt: str
    user_prompt: str
    variables: dict[str, Any]
    parse: Callable[[Any], Any]
    logger: Any
    label: str
    batch_size: int
    invalid_message: str
    final_keep_message: str
    max_tokens: int | None = None
    temperature: float | None = None
    response_model: type | None = None
    reasoning_effort: str | None = None
    chat_model_kwargs: dict[str, Any] | None = None
    model_tools: tuple[Any, ...] = ()
    max_tool_rounds: int | None = None


class JsonPromptRunner:
    def __init__(self, llm_provider, usage_runtime=None):
        self._llm_provider = llm_provider
        self._usage_runtime = usage_runtime

    def invoke(self, request: JsonPromptRequest):
        last_failure = "unknown failure"
        max_tool_rounds = (
            _require_max_tool_rounds(request.max_tool_rounds)
            if request.model_tools
            else None
        )
        for attempt in range(2):
            try:
                usage_chat_kwargs = (
                    self._usage_runtime.hooks.chat_model_kwargs()
                    if self._usage_runtime is not None
                    else None
                )
                params = merge_chat_model_kwargs(
                    request.chat_model_kwargs,
                    usage_chat_kwargs,
                    model=request.model,
                    reasoning_effort=request.reasoning_effort,
                )
                if request.max_tokens is not None:
                    params["max_tokens"] = request.max_tokens
                if request.temperature is not None:
                    params["temperature"] = request.temperature
                chat = self._llm_provider.get_chat_model(**params)
                system_prompt = _system_prompt_with_tool_guidance(
                    request.system_prompt,
                    request.model_tools,
                )
                prompt = ChatPromptTemplate.from_messages(
                    [
                        SystemMessage(content=system_prompt),
                        ("user", request.user_prompt),
                    ]
                )
                parsed = None
                structured_output = getattr(chat, "with_structured_output", None)
                if (
                    not request.model_tools
                    and request.response_model is not None
                    and callable(structured_output)
                ):
                    try:
                        parsed = request.parse(
                            (
                                prompt
                                | structured_output(
                                    request.response_model,
                                    method="function_calling",
                                )
                            ).invoke(request.variables)
                        )
                    except Exception as exc:
                        last_failure = f"structured validation failed: {exc}"
                if parsed is None:
                    if request.model_tools:
                        response_text = _invoke_with_model_tools(
                            chat,
                            prompt,
                            request.variables,
                            request.model_tools,
                            max_tool_rounds=max_tool_rounds,
                        )
                    else:
                        response_text = (prompt | chat | StrOutputParser()).invoke(
                            request.variables
                        )
                    parsed = request.parse(response_text)
                if parsed is not None:
                    return parsed
                last_failure = request.invalid_message
            except Exception as exc:
                if isinstance(exc, ModelToolConfigurationError):
                    raise
                last_failure = str(exc)
            if attempt == 0:
                request.logger.warning(
                    "%s failed for %d candidates; retrying once: %s",
                    request.label,
                    request.batch_size,
                    last_failure,
                )
        request.logger.warning(
            "%s failed for %d candidates; %s: %s",
            request.label,
            request.batch_size,
            request.final_keep_message,
            last_failure,
        )
        return None


def invoke_langchain_json_prompt_with_retry(
    llm_provider,
    usage_runtime=None,
    *,
    model,
    system_prompt,
    user_prompt,
    variables,
    parse,
    logger,
    label,
    batch_size,
    invalid_message,
    final_keep_message,
    max_tokens=None,
    temperature=None,
    response_model=None,
    reasoning_effort=None,
    chat_model_kwargs=None,
    model_tools=(),
    max_tool_rounds=None,
):
    return JsonPromptRunner(llm_provider, usage_runtime).invoke(
        JsonPromptRequest(
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            variables=variables,
            parse=parse,
            logger=logger,
            label=label,
            batch_size=batch_size,
            invalid_message=invalid_message,
            final_keep_message=final_keep_message,
            max_tokens=max_tokens,
            temperature=temperature,
            response_model=response_model,
            reasoning_effort=reasoning_effort,
            chat_model_kwargs=chat_model_kwargs,
            model_tools=tuple(model_tools or ()),
            max_tool_rounds=max_tool_rounds,
        )
    )


def _system_prompt_with_tool_guidance(
    system_prompt: str, tools: tuple[Any, ...]
) -> str:
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


def _tool_contract_sections(tools: tuple[Any, ...]) -> list[str]:
    sections = []
    for tool in tools:
        metadata = getattr(tool, "metadata", None) or {}
        if not isinstance(metadata, dict):
            continue
        contract = _clip_tool_contract(str(metadata.get("metis_contract") or ""))
        if not contract:
            continue
        name = getattr(tool, "name", "tool")
        sections.append(f"[{name}]\n{contract}")
    return sections


def _clip_tool_contract(contract: str) -> str:
    text = contract.strip()
    if len(text) <= _MAX_TOOL_CONTRACT_CHARS:
        return text
    return text[:_MAX_TOOL_CONTRACT_CHARS].rstrip() + "\n[contract truncated]"


def _require_max_tool_rounds(value: int | None) -> int:
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


def _invoke_with_model_tools(
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
                content = tool.invoke(args)
            except Exception as exc:
                status = "error"
                content = f"Tool {name!r} failed: {exc}"
            messages.append(
                ToolMessage(
                    content=str(content),
                    name=name,
                    tool_call_id=tool_call_id,
                    status=status,
                )
            )
    return _message_content_text(last_response)


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
