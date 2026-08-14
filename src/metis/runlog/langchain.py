# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import Any

from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.callbacks.base import BaseCallbackManager

from .session import Span
from .session import bump
from .session import current_runlog


class RunLogCallbackHandler(BaseCallbackHandler):
    """Records physical LangChain model calls under the current logical prompt."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._spans: dict[str, Span] = {}

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: Any,
        **kwargs: Any,
    ) -> Any:
        self._start(
            run_id,
            serialized,
            {
                "messages": messages,
                "invocation": kwargs.get("invocation_params") or {},
                "tags": kwargs.get("tags") or [],
                "metadata": kwargs.get("metadata") or {},
            },
        )
        return None

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: Any,
        **kwargs: Any,
    ) -> Any:
        self._start(
            run_id,
            serialized,
            {
                "prompts": prompts,
                "invocation": kwargs.get("invocation_params") or {},
                "tags": kwargs.get("tags") or [],
                "metadata": kwargs.get("metadata") or {},
            },
        )
        return None

    def on_llm_end(self, response: Any, *, run_id: Any, **kwargs: Any) -> Any:
        call = self._pop(run_id)
        if call is None:
            return None
        usage = _usage(response)
        model = _model_name(response)
        if usage:
            call.event("usage", {"model": model, **usage})
            bump("input_tokens", usage["input_tokens"])
            bump("output_tokens", usage["output_tokens"])
            bump("total_tokens", usage["total_tokens"])
        bump("llm_calls")
        call.end(
            attributes={
                "response": _response_payload(response),
                "model": model,
                "usage": usage,
            }
        )
        return None

    def on_llm_error(self, error: BaseException, *, run_id: Any, **kwargs: Any) -> Any:
        call = self._pop(run_id)
        if call is None:
            return None
        bump("llm_calls")
        call.end(status="error", exc=error)
        return None

    def _start(
        self,
        run_id: Any,
        serialized: dict[str, Any],
        attributes: dict[str, Any],
    ) -> None:
        session = current_runlog()
        if session is None:
            return
        name = _serialized_name(serialized)
        call = session.span(
            "llm.call",
            name,
            {
                "langchain_run_id": str(run_id),
                "provider": serialized,
                **attributes,
            },
        )
        if not isinstance(call, Span):
            return
        with self._lock:
            self._spans[str(run_id)] = call

    def _pop(self, run_id: Any) -> Span | None:
        with self._lock:
            return self._spans.pop(str(run_id), None)


RUNLOG_CALLBACK_HANDLER = RunLogCallbackHandler()


def ensure_runlog_callback(callbacks: Any) -> Any:
    """Returns callbacks with the singleton runlog handler included once."""

    if callbacks is None:
        return [RUNLOG_CALLBACK_HANDLER]
    if isinstance(callbacks, list):
        if any(callback is RUNLOG_CALLBACK_HANDLER for callback in callbacks):
            return callbacks
        return [*callbacks, RUNLOG_CALLBACK_HANDLER]
    if isinstance(callbacks, tuple):
        if any(callback is RUNLOG_CALLBACK_HANDLER for callback in callbacks):
            return list(callbacks)
        return [*callbacks, RUNLOG_CALLBACK_HANDLER]
    if isinstance(callbacks, BaseCallbackManager):
        callbacks.add_handler(RUNLOG_CALLBACK_HANDLER, inherit=True)
        return callbacks
    return callbacks


def _serialized_name(serialized: dict[str, Any]) -> str:
    name = serialized.get("name")
    if name:
        return str(name)
    identifiers = serialized.get("id")
    if isinstance(identifiers, list) and identifiers:
        return str(identifiers[-1])
    return "model"


def _usage(response: Any) -> dict[str, int]:
    llm_output = getattr(response, "llm_output", None) or {}
    token_usage = llm_output.get("token_usage") if isinstance(llm_output, dict) else {}
    if not isinstance(token_usage, dict):
        token_usage = {}
    input_tokens = _positive_int(
        token_usage.get("prompt_tokens") or token_usage.get("input_tokens")
    )
    output_tokens = _positive_int(
        token_usage.get("completion_tokens") or token_usage.get("output_tokens")
    )
    total_tokens = _positive_int(token_usage.get("total_tokens"))
    if not any((input_tokens, output_tokens, total_tokens)):
        for generation_list in getattr(response, "generations", None) or []:
            if not isinstance(generation_list, Iterable):
                continue
            for generation in generation_list:
                message = getattr(generation, "message", generation)
                metadata = getattr(message, "usage_metadata", None) or {}
                if not isinstance(metadata, dict):
                    continue
                input_tokens += _positive_int(metadata.get("input_tokens"))
                output_tokens += _positive_int(metadata.get("output_tokens"))
                total_tokens += _positive_int(metadata.get("total_tokens"))
    if total_tokens <= 0:
        total_tokens = input_tokens + output_tokens
    if not any((input_tokens, output_tokens, total_tokens)):
        return {}
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


def _model_name(response: Any) -> str:
    llm_output = getattr(response, "llm_output", None) or {}
    if isinstance(llm_output, dict) and llm_output.get("model_name"):
        return str(llm_output["model_name"])
    for generation_list in getattr(response, "generations", None) or []:
        for generation in (
            generation_list if isinstance(generation_list, Iterable) else ()
        ):
            message = getattr(generation, "message", generation)
            metadata = getattr(message, "response_metadata", None) or {}
            if isinstance(metadata, dict):
                name = metadata.get("model_name") or metadata.get("model")
                if name:
                    return str(name)
    return "unknown"


def _response_payload(response: Any) -> dict[str, Any]:
    generations = []
    for generation_list in getattr(response, "generations", None) or []:
        row = []
        for generation in (
            generation_list if isinstance(generation_list, Iterable) else ()
        ):
            message = getattr(generation, "message", None)
            row.append(
                {
                    "text": getattr(generation, "text", None),
                    "message": message,
                    "generation_info": getattr(generation, "generation_info", None),
                }
            )
        generations.append(row)
    return {
        "generations": generations,
        "llm_output": getattr(response, "llm_output", None),
    }


def _positive_int(value: Any) -> int:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed > 0 else 0
