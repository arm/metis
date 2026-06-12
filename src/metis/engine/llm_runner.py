# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Any, Callable

from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis.chat_model_options import merge_chat_model_kwargs


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


class JsonPromptRunner:
    def __init__(self, llm_provider, usage_runtime=None):
        self._llm_provider = llm_provider
        self._usage_runtime = usage_runtime

    def invoke(self, request: JsonPromptRequest):
        last_failure = "unknown failure"
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
                prompt = ChatPromptTemplate.from_messages(
                    [
                        SystemMessage(content=request.system_prompt),
                        ("user", request.user_prompt),
                    ]
                )
                parsed = None
                structured_output = getattr(chat, "with_structured_output", None)
                if request.response_model is not None and callable(structured_output):
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
                    parsed = request.parse(
                        (prompt | chat | StrOutputParser()).invoke(request.variables)
                    )
                if parsed is not None:
                    return parsed
                last_failure = request.invalid_message
            except Exception as exc:
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
        )
    )
