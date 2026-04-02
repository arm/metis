from __future__ import annotations

from copy import deepcopy
from threading import Lock
from typing import Any


def _empty_summary() -> dict[str, Any]:
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "by_model": {},
        "by_operation": {},
    }


def _increment(summary: dict[str, Any], event: dict[str, Any]) -> None:
    input_tokens = int(event.get("input_tokens") or 0)
    output_tokens = int(event.get("output_tokens") or 0)
    total_tokens = int(event.get("total_tokens") or (input_tokens + output_tokens))
    model_name = str(event.get("model") or "unknown")
    operation = str(event.get("operation") or "llm")

    summary["input_tokens"] += input_tokens
    summary["output_tokens"] += output_tokens
    summary["total_tokens"] += total_tokens

    model_summary = summary["by_model"].setdefault(
        model_name,
        {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
        },
    )
    model_summary["input_tokens"] += input_tokens
    model_summary["output_tokens"] += output_tokens
    model_summary["total_tokens"] += total_tokens

    operation_summary = summary["by_operation"].setdefault(
        operation,
        {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
        },
    )
    operation_summary["input_tokens"] += input_tokens
    operation_summary["output_tokens"] += output_tokens
    operation_summary["total_tokens"] += total_tokens


class UsageCollector:
    def __init__(self):
        self._lock = Lock()
        self._summary = _empty_summary()
        self._scopes: dict[str, dict[str, Any]] = {}

    def reset(self) -> None:
        with self._lock:
            self._summary = _empty_summary()
            self._scopes = {}

    def record(
        self,
        *,
        scope_id: str | None,
        operation: str | None,
        model: str | None,
        input_tokens: int,
        output_tokens: int,
        total_tokens: int | None = None,
    ) -> None:
        event = {
            "operation": operation or "llm",
            "model": model or "unknown",
            "input_tokens": max(0, int(input_tokens or 0)),
            "output_tokens": max(0, int(output_tokens or 0)),
            "total_tokens": max(
                0,
                (
                    int(total_tokens)
                    if total_tokens is not None
                    else int(input_tokens or 0) + int(output_tokens or 0)
                ),
            ),
        }
        with self._lock:
            _increment(self._summary, event)
            if scope_id:
                scoped = self._scopes.setdefault(scope_id, _empty_summary())
                _increment(scoped, event)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return deepcopy(self._summary)

    def snapshot_scope(self, scope_id: str) -> dict[str, Any]:
        with self._lock:
            return deepcopy(self._scopes.get(scope_id, _empty_summary()))
