from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from langchain_core.callbacks.base import BaseCallbackHandler

from .collector import UsageCollector
from .context import current_operation, current_scope


def _as_int(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if parsed > 0 else 0


def _extract_usage_metadata(response) -> tuple[int, int, int]:
    llm_output = getattr(response, "llm_output", None) or {}
    token_usage = {}
    if isinstance(llm_output, dict):
        token_usage = llm_output.get("token_usage") or {}
    if isinstance(token_usage, dict) and token_usage:
        input_tokens = _as_int(
            token_usage.get("prompt_tokens") or token_usage.get("input_tokens")
        )
        output_tokens = _as_int(
            token_usage.get("completion_tokens") or token_usage.get("output_tokens")
        )
        total_tokens = _as_int(token_usage.get("total_tokens"))
        if total_tokens <= 0:
            total_tokens = input_tokens + output_tokens
        if input_tokens or output_tokens or total_tokens:
            return input_tokens, output_tokens, total_tokens

    input_tokens = 0
    output_tokens = 0
    total_tokens = 0
    generations = getattr(response, "generations", None) or []
    for generation_list in generations:
        if not isinstance(generation_list, Iterable):
            continue
        for generation in generation_list:
            message = getattr(generation, "message", None)
            usage_metadata = getattr(message, "usage_metadata", None) or {}
            if not isinstance(usage_metadata, dict):
                continue
            input_tokens += _as_int(usage_metadata.get("input_tokens"))
            output_tokens += _as_int(usage_metadata.get("output_tokens"))
            total_tokens += _as_int(usage_metadata.get("total_tokens"))
    if total_tokens <= 0:
        total_tokens = input_tokens + output_tokens
    return input_tokens, output_tokens, total_tokens


def _extract_model_name(response) -> str:
    llm_output = getattr(response, "llm_output", None) or {}
    if isinstance(llm_output, dict):
        model_name = str(llm_output.get("model_name") or "").strip()
        if model_name:
            return model_name
    generations = getattr(response, "generations", None) or []
    for generation_list in generations:
        if not isinstance(generation_list, Iterable):
            continue
        for generation in generation_list:
            message = getattr(generation, "message", None)
            response_metadata = getattr(message, "response_metadata", None) or {}
            if not isinstance(response_metadata, dict):
                continue
            model_name = str(
                response_metadata.get("model_name") or response_metadata.get("model")
            ).strip()
            if model_name:
                return model_name
    return "unknown"


class UsageCallbackHandler(BaseCallbackHandler):
    def __init__(self, collector: UsageCollector):
        self._collector = collector

    def on_llm_end(self, response, **kwargs: Any) -> Any:
        scope_id = current_scope()
        if not scope_id:
            return None
        input_tokens, output_tokens, total_tokens = _extract_usage_metadata(response)
        if input_tokens <= 0 and output_tokens <= 0 and total_tokens <= 0:
            return None
        self._collector.record(
            scope_id=scope_id,
            operation=current_operation(),
            model=_extract_model_name(response),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
        )
        return None
