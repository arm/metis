# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import math
import random
import ssl
import time
from collections.abc import Callable
from concurrent.futures import CancelledError
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any

from langchain_core.messages import HumanMessage
from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from openai.types.responses import ResponseError

from metis import runlog
from metis.chat_model_options import merge_chat_model_kwargs
from metis.engine.concurrency import _cancellation_checkpoint
from metis.engine.concurrency import _current_cancellation
from metis.engine.model_tool_runner import ModelInputLimitError
from metis.engine.model_tool_runner import ModelOutputLimitError
from metis.engine.model_tool_runner import ModelResponseIncompleteError
from metis.engine.model_tool_runner import ModelToolConfigurationError
from metis.engine.model_tool_runner import ModelToolResultError
from metis.engine.model_tool_runner import invoke_model_with_tools
from metis.engine.model_tool_runner import model_messages_token_count
from metis.engine.model_tool_runner import model_tool_system_prompt
from metis.engine.model_tool_runner import require_completed_model_response
from metis.engine.model_tool_runner import require_max_tool_rounds
from metis.engine.model_tool_runner import require_model_input_budget
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
    max_input_tokens: int | None = None
    on_tool_result: Callable[[str, dict[str, Any], str], None] | None = None
    on_tool_error: Callable[[], None] | None = None


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
    return model_messages_token_count(messages, token_counter)


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
        _cancellation_checkpoint()
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
            _cancellation_checkpoint()
            return parsed

    def _invoke_attempts(self, request: JsonPromptRequest):
        last_failure = "unknown failure"
        confirmed_output_limit = False
        incomplete_response: ModelResponseIncompleteError | None = None
        tool_evidence: tuple[str, ...] = ()
        configured_retries = getattr(self._llm_provider, "max_retries", None)
        max_transport_retries = (
            max(0, configured_retries)
            if isinstance(configured_retries, int)
            else self._max_attempts - 1
        )
        transport_retries = 0
        output_attempts = 0
        token_counter = (
            (lambda text: self._llm_provider.count_tokens(text, model=request.model))
            if request.max_input_tokens is not None
            else None
        )
        max_tool_rounds = (
            require_max_tool_rounds(request.max_tool_rounds)
            if request.model_tools
            else None
        )
        # Template errors are configuration failures, not provider retry failures.
        prompt = _json_chat_prompt(
            request.system_prompt, request.user_prompt, request.model_tools
        )
        prompt.invoke(request.variables)
        for attempt in range(self._max_attempts + max_transport_retries):
            _cancellation_checkpoint()
            response_text: Any = None
            parsed: Any = None
            attempt_error: Exception | None = None
            attempt_failure = request.invalid_message
            with runlog.span(
                "attempt",
                f"{request.label}:{attempt + 1}",
                {
                    "attempt": attempt + 1,
                    "max_attempts": self._max_attempts + max_transport_retries,
                    "max_output_attempts": self._max_attempts,
                    "max_transport_retries": max_transport_retries,
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
                    params["max_retries"] = 0
                    params["callbacks"] = ensure_runlog_callback(
                        params.get("callbacks")
                    )
                    if request.max_tokens is not None:
                        params["max_tokens"] = request.max_tokens
                    if request.temperature is not None:
                        params["temperature"] = request.temperature
                    _cancellation_checkpoint()
                    chat = self._llm_provider.get_chat_model(**params)
                    _cancellation_checkpoint()
                    active_tools = request.model_tools if not tool_evidence else ()
                    if tool_evidence:
                        prompt = _json_chat_prompt(
                            request.system_prompt,
                            request.user_prompt,
                            request.model_tools,
                            tool_evidence,
                        )
                    if request.max_input_tokens is not None:
                        require_model_input_budget(
                            prompt.invoke(request.variables).to_messages(),
                            token_counter,
                            request.max_input_tokens,
                        )
                    used_structured_output = False
                    structured_output = getattr(chat, "with_structured_output", None)
                    if (
                        not active_tools
                        and request.response_model is not None
                        and callable(structured_output)
                    ):
                        used_structured_output = True
                        structured_model = structured_output(
                            request.response_model,
                            method="function_calling",
                            include_raw=True,
                        )
                        _cancellation_checkpoint()
                        structured_result = (prompt | structured_model).invoke(
                            request.variables
                        )
                        _cancellation_checkpoint()
                        if not isinstance(structured_result, dict):
                            raise TypeError(
                                "Structured model response did not include raw output"
                            )
                        raw_response = structured_result.get("raw")
                        response_text = getattr(raw_response, "content", None)
                        parsing_error = structured_result.get("parsing_error")
                        if isinstance(parsing_error, CancelledError):
                            raise parsing_error
                        require_completed_model_response(
                            raw_response, tool_evidence=tool_evidence
                        )
                        try:
                            parsed = request.parse(
                                None
                                if parsing_error is not None
                                else structured_result.get("parsed")
                            )
                        except CancelledError:
                            raise
                        except Exception as exc:
                            attempt_failure = f"structured validation failed: {exc}"
                        if parsing_error is not None:
                            parsed = None
                            attempt_failure = (
                                f"structured validation failed: {parsing_error}"
                            )
                    if parsed is None and not used_structured_output:
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
                                on_tool_result=request.on_tool_result,
                                on_tool_error=request.on_tool_error,
                            )
                            _cancellation_checkpoint()
                            tool_evidence = observed_evidence
                        else:
                            _cancellation_checkpoint()
                            response = (prompt | chat).invoke(request.variables)
                            _cancellation_checkpoint()
                            require_completed_model_response(
                                response, tool_evidence=tool_evidence
                            )
                            response_text = StrOutputParser().invoke(response)
                        try:
                            parsed = request.parse(response_text)
                        except CancelledError:
                            raise
                        except Exception as exc:
                            attempt_failure = f"response validation failed: {exc}"
                    if parsed is not None:
                        _cancellation_checkpoint()
                        attempt_span.end(
                            attributes={
                                "response_text": response_text,
                                "parsed": parsed,
                            }
                        )
                        _cancellation_checkpoint()
                        return parsed
                except CancelledError:
                    raise
                except ModelOutputLimitError as exc:
                    _cancellation_checkpoint()
                    confirmed_output_limit = True
                    attempt_failure = str(exc)
                    tool_evidence = exc.tool_evidence
                except ModelResponseIncompleteError as exc:
                    _cancellation_checkpoint()
                    incomplete_response = exc
                    attempt_failure = str(exc)
                    tool_evidence = exc.tool_evidence
                except Exception as exc:
                    _cancellation_checkpoint()
                    if isinstance(
                        exc,
                        (
                            ModelToolConfigurationError,
                            ModelInputLimitError,
                            ModelToolResultError,
                        ),
                    ):
                        raise
                    if _certificate_verification_failed(exc):
                        raise ModelProviderConfigurationError(
                            "TLS certificate verification failed while contacting "
                            "the model provider. Install the required CA certificate "
                            "in the Python environment before retrying."
                        ) from exc
                    attempt_error = exc
                    attempt_failure = str(exc)
                _cancellation_checkpoint()
                last_failure = attempt_failure
                attempt_span.end(
                    status="error" if attempt_error is not None else "inconclusive",
                    attributes={
                        "response_text": response_text,
                        "failure": last_failure,
                    },
                    exc=attempt_error,
                )
            if attempt_error is not None:
                if transport_retries >= max_transport_retries:
                    raise attempt_error
                backoff_seconds = _provider_retry_delay(
                    attempt_error,
                    max(
                        0.0,
                        min(self._retry_backoff_seconds * (2**transport_retries), 30.0)
                        * random.uniform(0.75, 1.0),
                    ),
                )
                transport_retries += 1
                retry_kind = "transport retry"
                retry_count = transport_retries
                retry_limit = max_transport_retries
            else:
                output_attempts += 1
                if output_attempts >= self._max_attempts:
                    break
                backoff_seconds = max(
                    0.0,
                    min(
                        self._retry_backoff_seconds * (2 ** (output_attempts - 1)), 30.0
                    ),
                )
                retry_kind = "attempt"
                retry_count = output_attempts
                retry_limit = self._max_attempts
            runlog.event(
                "retry",
                {
                    "operation": "llm",
                    "label": request.label,
                    "attempt": attempt + 2,
                    "max_attempts": self._max_attempts + max_transport_retries,
                    "max_output_attempts": self._max_attempts,
                    "transport_retries": transport_retries,
                    "backoff_ms": backoff_seconds * 1000.0,
                    "reason": last_failure,
                },
            )
            request.logger.warning(
                "%s failed for %d candidates; retrying (%s %d/%d): %s",
                request.label,
                request.batch_size,
                retry_kind,
                retry_count,
                retry_limit,
                last_failure,
            )
            if backoff_seconds > 0:
                if _current_cancellation.get() is None:
                    time.sleep(backoff_seconds)
                else:
                    deadline = time.monotonic() + backoff_seconds
                    while (remaining := deadline - time.monotonic()) > 0:
                        _cancellation_checkpoint()
                        time.sleep(min(remaining, 0.1))
        _cancellation_checkpoint()
        if confirmed_output_limit:
            if request.on_output_limit is not None:
                request.on_output_limit()
            else:
                raise ModelOutputLimitError(
                    f"{request.label} reached the model output token limit "
                    f"after {self._max_attempts} attempts",
                    tool_evidence=tool_evidence,
                )
        elif incomplete_response is not None:
            raise incomplete_response
        request.logger.warning(
            "%s failed for %d candidates; %s: %s",
            request.label,
            request.batch_size,
            request.final_keep_message,
            last_failure,
        )
        _cancellation_checkpoint()
        return None


def _provider_retry_delay(error: Exception, default_seconds: float) -> float:
    response_error = (
        error.args[0] if isinstance(error, ValueError) and error.args else None
    )
    if isinstance(response_error, ResponseError) and response_error.code not in {
        "server_error",
        "rate_limit_exceeded",
        "vector_store_timeout",
        "failed_to_download_image",
    }:
        raise error
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", {}) or {}
    status_code = getattr(error, "status_code", getattr(response, "status_code", None))
    if (
        headers.get("x-should-retry") == "false"
        or getattr(error, "code", None) == "insufficient_quota"
        or (
            isinstance(status_code, int)
            and status_code not in {408, 409, 429}
            and 400 <= status_code < 500
            and headers.get("x-should-retry") != "true"
        )
    ):
        raise error
    retry_after: float | None = None
    if headers.get("retry-after-ms") is not None:
        try:
            retry_after = float(headers["retry-after-ms"]) / 1000.0
        except (TypeError, ValueError):
            pass
        if retry_after is not None and (
            not math.isfinite(retry_after) or retry_after < 0
        ):
            retry_after = None
    if retry_after is None and headers.get("retry-after") is not None:
        value = headers["retry-after"]
        try:
            retry_after = float(value)
        except (TypeError, ValueError):
            try:
                retry_after = parsedate_to_datetime(value).timestamp() - time.time()
            except (TypeError, ValueError, OverflowError):
                pass
    if retry_after is not None and math.isfinite(retry_after):
        if retry_after > 120:
            raise error
        if retry_after >= 0:
            return retry_after
    return default_seconds


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
