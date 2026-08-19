from __future__ import annotations

from typing import Any

from langchain_core.callbacks.base import BaseCallbackHandler

from metis.runlog.langchain import extract_response_model_name
from metis.runlog.langchain import extract_response_usage

from .collector import UsageCollector
from .context import current_operation, current_scope


class UsageCallbackHandler(BaseCallbackHandler):
    def __init__(self, collector: UsageCollector):
        self._collector = collector

    def on_llm_end(self, response: Any, **kwargs: Any) -> Any:
        scope_id = current_scope()
        usage = extract_response_usage(response)
        if not usage:
            return None
        self._collector.record(
            scope_id=scope_id,
            operation=current_operation(),
            model=extract_response_model_name(response),
            **usage,
        )
        return None
