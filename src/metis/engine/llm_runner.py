# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from langchain_core.messages import HumanMessage
from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from metis import runlog
from metis.chat_model_options import merge_chat_model_kwargs
from metis.engine.model_tool_runner import ModelToolConfigurationError
from metis.engine.model_tool_runner import invoke_model_with_tools
from metis.engine.model_tool_runner import model_tool_system_prompt
from metis.engine.model_tool_runner import require_max_tool_rounds
from metis.runlog.langchain import ensure_runlog_callback


class ModelProviderConfigurationError(RuntimeError):
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
    on_output_limit: Callable[[], None] | None = None


def rendered_prompt_token_count(
    token_counter: Callable[[str], int],
    *,
    system_prompt: str,
    user_prompt: str,
    variables: dict[str, Any],
    model_tools: tuple[Any, ...] = (),
) -> int:
    prompt = _json_chat_prompt(system_prompt, user_prompt, model_tools)
    messages = prompt.invoke(variables).to_messages()
    return sum(
        token_counter(
            message.content
            if isinstance(message.content, str)
            else str(message.content)
        )
        for message in messages
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
        confirmed_output_limit = False
        tool_evidence: tuple[str, ...] = ()
        max_tool_rounds = (
            require_max_tool_rounds(request.max_tool_rounds)
            if request.model_tools
            else None
        )
        for attempt in range(self._max_attempts):
            response_text: Any = None
            parsed: Any = None
            attempt_error: Exception | None = None
            attempt_failure = request.invalid_message
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
                    if attempt == 0:
                        params["max_retries"] = 0
                    params["callbacks"] = ensure_runlog_callback(
                        params.get("callbacks")
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
                    used_structured_output = False
                    structured_output = getattr(chat, "with_structured_output", None)
                    if (
                        not active_tools
                        and request.response_model is not None
                        and callable(structured_output)
                    ):
                        used_structured_output = True
                        structured_result = (
                            prompt
                            | structured_output(
                                request.response_model,
                                method="function_calling",
                                include_raw=True,
                            )
                        ).invoke(request.variables)
                        if not isinstance(structured_result, dict):
                            raise TypeError(
                                "Structured model response did not include raw output"
                            )
                        raw_response = structured_result.get("raw")
                        response_text = getattr(raw_response, "content", None)
                        parsing_error = structured_result.get("parsing_error")
                        if parsing_error is not None:
                            attempt_failure = (
                                f"structured validation failed: {parsing_error}"
                            )
                        else:
                            try:
                                parsed = request.parse(structured_result.get("parsed"))
                            except Exception as exc:
                                attempt_failure = f"structured validation failed: {exc}"
                        if parsed is None and _response_reached_output_limit(
                            raw_response
                        ):
                            confirmed_output_limit = True
                    if parsed is None and not used_structured_output:
                        if active_tools:
                            assert max_tool_rounds is not None
                            response_text, observed_evidence = invoke_model_with_tools(
                                chat,
                                prompt,
                                request.variables,
                                active_tools,
                                max_tool_rounds=max_tool_rounds,
                            )
                            parsed = request.parse(response_text)
                            if parsed is None:
                                tool_evidence = observed_evidence
                        else:
                            response = (prompt | chat).invoke(request.variables)
                            response_text = StrOutputParser().invoke(response)
                            try:
                                parsed = request.parse(response_text)
                            finally:
                                if parsed is None and _response_reached_output_limit(
                                    response
                                ):
                                    confirmed_output_limit = True
                    if parsed is not None:
                        attempt_span.end(
                            attributes={
                                "response_text": response_text,
                                "parsed": parsed,
                            }
                        )
                        return parsed
                except Exception as exc:
                    if isinstance(exc, ModelToolConfigurationError):
                        raise
                    if _certificate_verification_failed(exc):
                        raise ModelProviderConfigurationError(
                            "TLS certificate verification failed while contacting "
                            "the model provider. Install the required CA certificate "
                            "in the Python environment before retrying."
                        ) from exc
                    attempt_error = exc
                    attempt_failure = str(exc)
                last_failure = attempt_failure
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
        if confirmed_output_limit and request.on_output_limit is not None:
            request.on_output_limit()
        request.logger.warning(
            "%s failed for %d candidates; %s: %s",
            request.label,
            request.batch_size,
            request.final_keep_message,
            last_failure,
        )
        return None


def _response_reached_output_limit(response: object) -> bool:
    for attribute in ("response_metadata", "additional_kwargs"):
        metadata = getattr(response, attribute, None)
        if not isinstance(metadata, dict):
            continue
        incomplete_details = metadata.get("incomplete_details")
        if (
            str(metadata.get("status", "")).strip().lower() == "incomplete"
            and isinstance(incomplete_details, dict)
            and str(incomplete_details.get("reason", "")).strip().lower()
            == "max_output_tokens"
        ):
            return True
        for key in ("finish_reason", "stop_reason", "stopReason"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip().lower() in {
                "length",
                "max_tokens",
            }:
                return True
    return False


def _certificate_verification_failed(error: BaseException) -> bool:
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        message = str(current).lower()
        if (
            "certificate_verify_failed" in message
            or "certificate verify failed" in message
        ):
            return True
        current = current.__cause__ or current.__context__
    return False


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
