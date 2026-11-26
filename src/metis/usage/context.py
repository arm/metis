from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Iterator

_scope_var: ContextVar[str | None] = ContextVar("metis_usage_scope", default=None)
_operation_var: ContextVar[str | None] = ContextVar(
    "metis_usage_operation", default=None
)


def current_scope() -> str | None:
    return _scope_var.get()


def current_operation() -> str | None:
    return _operation_var.get()


@contextmanager
def _set(var: ContextVar[str | None], value: str) -> Iterator[None]:
    token: Token[str | None] = var.set(value)
    try:
        yield
    finally:
        var.reset(token)


@contextmanager
def usage_scope(scope_id: str) -> Iterator[None]:
    with _set(_scope_var, scope_id):
        yield


@contextmanager
def usage_operation(operation: str) -> Iterator[None]:
    with _set(_operation_var, operation):
        yield
