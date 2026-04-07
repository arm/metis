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
def usage_scope(scope_id: str) -> Iterator[None]:
    token: Token[str | None] = _scope_var.set(scope_id)
    try:
        yield
    finally:
        _scope_var.reset(token)


@contextmanager
def usage_operation(operation: str) -> Iterator[None]:
    token: Token[str | None] = _operation_var.set(operation)
    try:
        yield
    finally:
        _operation_var.reset(token)
