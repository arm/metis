# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import time
from collections.abc import Callable
from concurrent.futures import CancelledError
from dataclasses import dataclass
from typing import Any

from langchain_core.messages import HumanMessage
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
from metis.engine.model_tool_runner import ModelOutputLimitError
from metis.engine.model_tool_runner import ModelInputLimitError
from metis.engine.model_tool_runner import _response_reached_output_limit
from metis.engine.model_tool_runner import model_messages_token_count
from metis.engine.model_tool_runner import require_model_input_budget


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
    max_input_tokens: int | None = None


def rendered_prompt_token_count(
    token_counter: Callable[[str], int],
    *,
    system_prompt: str,
    user_prompt: str,
    variables: dict[str, Any],
    model_tools: tuple[Any, ...] = (),
) -> int:
    prompt = _json_chat_prompt(system_prompt, user_prompt, model_tools)
    return model_messages_token_count(
        prompt.invoke(variables).to_messages(), token_counter
    )


def _json_chat_prompt(
    system_prompt: str,
    user_prompt: str,
    model_tools: tuple[Any, ...] = (),
    tool_evidence: tuple[str, ...] = (),
) -> ChatPromptTemplate:
    rendered_system_prompt = model_tool_system_prompt(
        system_prompt,
        model_tools,
        tools_available=not tool_evidence,
    )
    messages: list[Any] = [
        SystemMessage(content=rendered_system_prompt),
        ("user", user_prompt),
    ]
    if tool_evidence:
        messages.append(
            HumanMessage(
                content=(
                    "BEGIN UNTRUSTED TOOL EVIDENCE\n"
                    + "\n\n".join(tool_evidence)
                    + "\nEND UNTRUSTED TOOL EVIDENCE"
                )
            )
        )
    return ChatPromptTemplate.from_messages(messages)


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
        output_limit_error = None
        tool_evidence: tuple[str, ...] = ()
        token_counter = (
            self._llm_provider.count_tokens
            if request.max_input_tokens is not None
            else None
        )
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
                active_tools = request.model_tools if not tool_evidence else ()
                prompt = _json_chat_prompt(
                    request.system_prompt,
                    request.user_prompt,
                    request.model_tools,
                    tool_evidence,
                )
                require_model_input_budget(
                    prompt.invoke(request.variables).to_messages(),
                    token_counter,
                    request.max_input_tokens,
                )
                parsed = None
                structured_output = getattr(chat, "with_structured_output", None)
                if (
                    not active_tools
                    and request.response_model is not None
                    and callable(structured_output)
                ):
                    structured_result = (
                        prompt
                        | structured_output(
                            request.response_model,
                            method="function_calling",
                            include_raw=True,
                        )
                    ).invoke(request.variables)
                    if _response_reached_output_limit(structured_result.get("raw")):
                        raise ModelOutputLimitError(
                            "model response reached its output token limit"
                        )
                    if structured_result.get("parsing_error") is not None:
                        raise ValueError(
                            f"structured validation failed: {structured_result['parsing_error']}"
                        )
                    parsed = request.parse(structured_result.get("parsed"))
                else:
                    if active_tools:
                        assert max_tool_rounds is not None
                        response_text, observed_evidence = invoke_model_with_tools(
                            chat,
                            prompt,
                            request.variables,
                            active_tools,
                            max_tool_rounds=max_tool_rounds,
                            token_counter=token_counter,
                            max_input_tokens=request.max_input_tokens,
                        )
                        parsed = request.parse(response_text)
                        if parsed is None:
                            tool_evidence = observed_evidence
                    else:
                        response = (prompt | chat).invoke(request.variables)
                        if _response_reached_output_limit(response):
                            raise ModelOutputLimitError(
                                "model response reached its output token limit"
                            )
                        response_text = StrOutputParser().invoke(response)
                        parsed = request.parse(response_text)
                if parsed is not None:
                    return parsed
                last_failure = request.invalid_message
            except CancelledError:
                raise
            except ModelOutputLimitError as exc:
                output_limit_error = exc
                tool_evidence = exc.tool_evidence
                last_failure = str(exc)
            except Exception as exc:
                if isinstance(exc, (ModelToolConfigurationError, ModelInputLimitError)):
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
        if output_limit_error is not None:
            raise ModelOutputLimitError(
                f"{request.label} reached the model output token limit "
                f"after {self._max_attempts} attempts"
            ) from output_limit_error
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
    max_input_tokens=None,
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
            max_input_tokens=max_input_tokens,
        )
    )
