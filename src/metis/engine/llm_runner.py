# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import time
from dataclasses import dataclass
from typing import Any, Callable

from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis import runlog
from metis.runlog.langchain import ensure_runlog_callback
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
        with runlog.span(
            "prompt",
            request.label,
            lambda: {
                "model": request.model,
                "system_prompt": request.system_prompt,
                "user_prompt": request.user_prompt,
                "variables": request.variables,
                "batch_size": request.batch_size,
                "response_model": (
                    request.response_model.__name__
                    if request.response_model is not None
                    else None
                ),
                "reasoning_effort": request.reasoning_effort,
                "tools": [
                    getattr(tool, "name", type(tool).__name__)
                    for tool in request.model_tools
                ],
                "max_tool_rounds": request.max_tool_rounds,
            },
        ) as prompt_span:
            parsed = self._invoke_attempts(request)
            prompt_span.end(
                status="ok" if parsed is not None else "inconclusive",
                attributes={"parsed": parsed},
            )
            return parsed

    def _invoke_attempts(self, request: JsonPromptRequest):
        last_failure = "unknown failure"
        max_tool_rounds = (
            require_max_tool_rounds(request.max_tool_rounds)
            if request.model_tools
            else None
        )
        for attempt in range(self._max_attempts):
            response_text: Any = None
            parsed: Any = None
            attempt_error: Exception | None = None
            with runlog.span(
                "attempt",
                f"{request.label}:{attempt + 1}",
                {
                    "attempt": attempt + 1,
                    "max_attempts": self._max_attempts,
                },
            ) as attempt_span:
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
                    params["callbacks"] = ensure_runlog_callback(
                        params.get("callbacks")
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
                        attempt_span.end(
                            attributes={
                                "response_text": response_text,
                                "parsed": parsed,
                            }
                        )
                        return parsed
                    last_failure = request.invalid_message
                except Exception as exc:
                    if isinstance(exc, ModelToolConfigurationError):
                        raise
                    attempt_error = exc
                    last_failure = str(exc)
                attempt_span.end(
                    status="error" if attempt_error is not None else "inconclusive",
                    attributes={
                        "response_text": response_text,
                        "failure": last_failure,
                    },
                    exc=attempt_error,
                )
            if attempt < self._max_attempts - 1:
                backoff_seconds = (
                    min(self._retry_backoff_seconds * (2**attempt), 30.0)
                    if self._retry_backoff_seconds > 0
                    else 0.0
                )
                runlog.event(
                    "retry",
                    {
                        "operation": "llm",
                        "label": request.label,
                        "attempt": attempt + 2,
                        "max_attempts": self._max_attempts,
                        "backoff_ms": backoff_seconds * 1000.0,
                        "reason": last_failure,
                    },
                )
                request.logger.warning(
                    "%s failed for %d candidates; retrying (attempt %d/%d): %s",
                    request.label,
                    request.batch_size,
                    attempt + 1,
                    self._max_attempts,
                    last_failure,
                )
                if backoff_seconds > 0:
                    time.sleep(backoff_seconds)
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
