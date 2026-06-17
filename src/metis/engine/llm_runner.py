# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import time
from dataclasses import dataclass
from typing import Any, Callable

from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.chat_model_options import merge_chat_model_kwargs
from metis.engine.model_tool_runner import (
    ModelToolConfigurationError,
    invoke_model_with_tools,
    model_tool_system_prompt,
    require_max_tool_rounds,
)


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
    def __init__(
        self,
        llm_provider,
        usage_runtime=None,
        *,
        max_attempts: int = 2,
        retry_backoff_seconds: float = 1.0,
    ):
        self._llm_provider = llm_provider
        self._usage_runtime = usage_runtime
        self._max_attempts = max(1, int(max_attempts))
        self._retry_backoff_seconds = float(retry_backoff_seconds)

    def invoke(self, request: JsonPromptRequest):
        last_failure = "unknown failure"
        max_tool_rounds = (
            require_max_tool_rounds(request.max_tool_rounds)
            if request.model_tools
            else None
        )
        for attempt in range(self._max_attempts):
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
                system_prompt = model_tool_system_prompt(
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
                        response_text = invoke_model_with_tools(
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
            if attempt < self._max_attempts - 1:
                request.logger.warning(
                    "%s failed for %d candidates; retrying (attempt %d/%d): %s",
                    request.label,
                    request.batch_size,
                    attempt + 1,
                    self._max_attempts,
                    last_failure,
                )
                if self._retry_backoff_seconds > 0:
                    time.sleep(min(self._retry_backoff_seconds * (2**attempt), 30.0))
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
