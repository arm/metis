from __future__ import annotations

from contextvars import copy_context


def submit_with_current_context(executor, fn, *args, **kwargs):
    return executor.submit(copy_context().run, fn, *args, **kwargs)
