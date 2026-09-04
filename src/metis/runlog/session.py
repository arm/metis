# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import contextlib
import json
import logging
import os
import platform
import subprocess
import sys
import threading
import time
import traceback
import uuid
from collections.abc import Callable
from collections.abc import Iterator
from collections.abc import Mapping
from contextvars import ContextVar
from contextvars import Token
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Any
from typing import Literal

from metis.json_io import write_json_atomic

from .encoding import PayloadEncoder
from .schema import event_explanation
from .schema import RunLogConfig
from .schema import SCHEMA_VERSION
from .schema import SpanStatus
from .schema import span_explanation

logger = logging.getLogger("metis")

Attributes = Mapping[str, Any] | Callable[[], Mapping[str, Any]] | None

_current_session: ContextVar[RunLogSession | None] = ContextVar(
    "metis_runlog_session", default=None
)
_current_span: ContextVar[str | None] = ContextVar("metis_runlog_span", default=None)


class Span:
    __slots__ = (
        "_ended",
        "_session",
        "_session_token",
        "_span_token",
        "_started",
        "explanation",
        "kind",
        "name",
        "parent_span_id",
        "span_id",
    )

    def __init__(
        self,
        session: RunLogSession,
        *,
        span_id: str,
        parent_span_id: str | None,
        kind: str,
        name: str,
        explanation: str,
        started: float,
    ) -> None:
        self._session = session
        self.span_id = span_id
        self.parent_span_id = parent_span_id
        self.kind = kind
        self.explanation = explanation
        self.name = name
        self._started = started
        self._ended = False
        self._session_token: Token[RunLogSession | None] | None = None
        self._span_token: Token[str | None] | None = None

    def __enter__(self) -> Span:
        self._session_token = _current_session.set(self._session)
        self._span_token = _current_span.set(self.span_id)
        return self

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:
        try:
            if not self._ended:
                if exc is None:
                    self.end()
                elif isinstance(exc, KeyboardInterrupt):
                    self.end(status="cancelled", exc=exc)
                else:
                    self.end(status="error", exc=exc)
        finally:
            if self._span_token is not None:
                _current_span.reset(self._span_token)
                self._span_token = None
            if self._session_token is not None:
                _current_session.reset(self._session_token)
                self._session_token = None
        return False

    @contextlib.contextmanager
    def activate(self) -> Iterator[Span]:
        if self._ended:
            raise RuntimeError("Cannot activate an ended run-log span")
        session_token = _current_session.set(self._session)
        span_token = _current_span.set(self.span_id)
        try:
            yield self
        finally:
            _current_span.reset(span_token)
            _current_session.reset(session_token)

    def event(
        self,
        name: str,
        attributes: Attributes = None,
        *,
        explanation: str | None = None,
        **extra: Any,
    ) -> None:
        if self._ended:
            raise RuntimeError("Cannot emit an event from an ended run-log span")
        self._session.event(
            name,
            attributes,
            span_id=self.span_id,
            explanation=explanation,
            **extra,
        )

    def end(
        self,
        *,
        status: SpanStatus = "ok",
        attributes: Attributes = None,
        exc: BaseException | None = None,
        **extra: Any,
    ) -> None:
        if self._ended:
            return
        self._ended = True
        payload = _merge_attributes(attributes, extra)
        self._session._write_span_end(
            span_id=self.span_id,
            parent_span_id=self.parent_span_id,
            kind=self.kind,
            name=self.name,
            started=self._started,
            status="error" if exc is not None and status == "ok" else status,
            explanation=self.explanation,
            attributes=payload,
            exc=exc,
        )


class _NullSpan:
    __slots__ = ()
    span_id = None
    parent_span_id = None

    def __enter__(self) -> _NullSpan:
        return self

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:
        return False

    @contextlib.contextmanager
    def activate(self) -> Iterator[_NullSpan]:
        yield self

    def event(
        self,
        name: str,
        attributes: Attributes = None,
        *,
        explanation: str | None = None,
        **extra: Any,
    ) -> None:
        return None

    def end(self, **kwargs: Any) -> None:
        return None


_NULL_SPAN = _NullSpan()


class RunLogSession:
    """One append-only v1 run-log bundle and its active span context."""

    def __init__(
        self,
        config: RunLogConfig | None = None,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self.config = config or RunLogConfig()
        self.run_id = uuid.uuid4().hex
        self._metadata = dict(metadata or {})
        self._lock = threading.RLock()
        self._file: Any = None
        self._encoder: PayloadEncoder | None = None
        self._seq = 0
        self._started_perf = time.perf_counter()
        self._started_at = _utc_now()
        self._entered = False
        self._closed = False
        self._failed = False
        self._failure_message: str | None = None
        self._outcome: SpanStatus = "ok"
        self._outcome_exc: BaseException | None = None
        self._counters: dict[str, int] = {}
        self._session_token: Token[RunLogSession | None] | None = None
        self._span_token: Token[str | None] | None = None
        self.root_span_id = uuid.uuid4().hex[:16]
        self.output_dir, self.ndjson_path, self.meta_path, self.blobs_dir = (
            _resolve_paths(self.config.path, self.run_id)
        )

    def __enter__(self) -> RunLogSession:
        if self._entered:
            raise RuntimeError("Run-log session is already open")
        created_ndjson = False
        try:
            self.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._file = self.ndjson_path.open("x", encoding="utf-8", buffering=1)
            created_ndjson = True
            self.ndjson_path.chmod(0o600)
            self._encoder = PayloadEncoder(self.blobs_dir, self.config)
            self._session_token = _current_session.set(self)
            self._span_token = _current_span.set(self.root_span_id)
            self._write_meta(complete=False)
            self._write_record(
                "span.start",
                span_id=self.root_span_id,
                parent_span_id=None,
                kind="run",
                name="metis",
                attributes=self._root_attributes(),
                strict=True,
            )
        except Exception:
            if self._file is not None:
                try:
                    self._file.close()
                except Exception:
                    pass
            self._reset_context()
            if created_ndjson:
                self.ndjson_path.unlink(missing_ok=True)
                self.meta_path.unlink(missing_ok=True)
            raise
        self._entered = True
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc is not None:
            self.set_outcome(
                "cancelled" if isinstance(exc, KeyboardInterrupt) else "error",
                exc=exc,
            )
        self.close()
        return False

    @property
    def enabled(self) -> bool:
        return self._entered and not self._closed and not self._failed

    @property
    def counters(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)

    def bind(self) -> contextlib.AbstractContextManager[RunLogSession]:
        return bind_runlog(self)

    def set_outcome(
        self,
        status: SpanStatus,
        *,
        exc: BaseException | None = None,
    ) -> None:
        with self._lock:
            if _status_rank(status) >= _status_rank(self._outcome):
                self._outcome = status
                self._outcome_exc = exc

    def bump(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + int(amount)

    def span(
        self,
        kind: str,
        name: str | None = None,
        attributes: Attributes = None,
        *,
        explanation: str | None = None,
        parent_span_id: str | None = None,
        **extra: Any,
    ) -> Span | _NullSpan:
        if not self.enabled:
            return _NULL_SPAN
        parent = parent_span_id
        if parent is None:
            parent = (
                _current_span.get()
                if _current_session.get() is self
                else self.root_span_id
            )
        span_name = name or kind
        resolved_explanation = explanation or span_explanation(kind, span_name)
        span_id = uuid.uuid4().hex[:16]
        started = time.perf_counter()
        self._write_record(
            "span.start",
            span_id=span_id,
            parent_span_id=parent,
            kind=kind,
            name=span_name,
            explanation=resolved_explanation,
            attributes=_merge_attributes(attributes, extra),
        )
        return Span(
            self,
            span_id=span_id,
            parent_span_id=parent,
            kind=kind,
            name=span_name,
            explanation=resolved_explanation,
            started=started,
        )

    def event(
        self,
        name: str,
        attributes: Attributes = None,
        *,
        span_id: str | None = None,
        explanation: str | None = None,
        **extra: Any,
    ) -> None:
        if not self.enabled:
            return
        owner = span_id
        if owner is None:
            owner = (
                _current_span.get()
                if _current_session.get() is self
                else self.root_span_id
            )
        self._write_record(
            "event",
            span_id=owner or self.root_span_id,
            name=name,
            attributes=_merge_attributes(attributes, extra),
            explanation=explanation,
        )

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._entered and not self._failed:
                self._write_span_end(
                    span_id=self.root_span_id,
                    parent_span_id=None,
                    kind="run",
                    name="metis",
                    started=self._started_perf,
                    status=self._outcome,
                    attributes={"totals": self.counters},
                    exc=self._outcome_exc,
                )
            if self._entered:
                try:
                    self._write_meta(complete=not self._failed)
                except Exception as exc:
                    self._disable_after_failure(exc)
        finally:
            self._closed = True
            if self._file is not None:
                try:
                    self._file.flush()
                except Exception as exc:
                    self._disable_after_failure(exc)
                try:
                    self._file.close()
                except Exception as exc:
                    self._disable_after_failure(exc)
            self._reset_context()

    def _reset_context(self) -> None:
        if self._span_token is not None:
            _current_span.reset(self._span_token)
            self._span_token = None
        if self._session_token is not None:
            _current_session.reset(self._session_token)
            self._session_token = None

    def _root_attributes(self) -> dict[str, Any]:
        return {
            **self._metadata,
            "started_at": self._started_at,
            "output_dir": str(self.output_dir),
            "ndjson_path": str(self.ndjson_path),
            "content": self.config.content,
        }

    def _write_span_end(
        self,
        *,
        span_id: str,
        parent_span_id: str | None,
        kind: str,
        name: str,
        started: float,
        status: SpanStatus,
        attributes: Attributes,
        explanation: str | None = None,
        exc: BaseException | None = None,
    ) -> None:
        error = _exception_payload(exc) if exc is not None else None
        self._write_record(
            "span.end",
            span_id=span_id,
            parent_span_id=parent_span_id,
            kind=kind,
            name=name,
            explanation=explanation,
            status=status,
            duration_ms=(time.perf_counter() - started) * 1000.0,
            error=error,
            attributes=attributes,
        )

    def _write_record(
        self,
        record_type: Literal["span.start", "span.end", "event"],
        *,
        span_id: str,
        name: str,
        attributes: Attributes,
        parent_span_id: str | None = None,
        explanation: str | None = None,
        kind: str | None = None,
        status: SpanStatus | None = None,
        duration_ms: float | None = None,
        error: Mapping[str, Any] | None = None,
        strict: bool = False,
    ) -> None:
        try:
            with self._lock:
                if self._failed and not strict:
                    return
                if self._file is None or self._encoder is None:
                    raise RuntimeError("Run-log session is not open")
                materialized_attributes = _materialize_attributes(attributes)
                resolved_explanation = (explanation or "").strip()
                if not resolved_explanation:
                    resolved_explanation = (
                        event_explanation(name, materialized_attributes)
                        if record_type == "event"
                        else span_explanation(kind or "operation", name)
                    )
                record: dict[str, Any] = {
                    "v": SCHEMA_VERSION,
                    "record": record_type,
                    "record_id": uuid.uuid4().hex[:16],
                    "ts": _utc_now(),
                    "mono_ns": time.perf_counter_ns(),
                    "seq": self._seq,
                    "run_id": self.run_id,
                    "span_id": span_id,
                    "name": name,
                    "explanation": resolved_explanation,
                    "thread": threading.current_thread().name,
                    "thread_id": threading.get_ident(),
                    "attributes": self._encoder.encode_mapping(materialized_attributes),
                }
                if record_type != "event":
                    record["parent_span_id"] = parent_span_id
                    record["kind"] = kind
                if status is not None:
                    record["status"] = status
                if duration_ms is not None:
                    record["duration_ms"] = round(duration_ms, 3)
                if error is not None:
                    record["error"] = self._encoder.encode_mapping(error)
                line = json.dumps(
                    record,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                )
                self._file.write(line + "\n")
                self._file.flush()
                self._seq += 1
        except Exception as exc:
            if strict or not self._entered:
                raise
            self._disable_after_failure(exc)

    def _write_meta(self, *, complete: bool) -> None:
        if self._encoder is None:
            return
        payload = {
            "v": SCHEMA_VERSION,
            "run_id": self.run_id,
            "started_at": self._started_at,
            "ended_at": _utc_now() if complete else None,
            "complete": complete,
            "status": self._outcome if complete else "running",
            "content": self.config.content,
            "ndjson_path": str(self.ndjson_path),
            "blobs_dir": str(self.blobs_dir),
            "metadata": self._encoder.encode_mapping(self._metadata),
            "totals": self.counters if complete else {},
        }
        self.meta_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_json_atomic(
            self.meta_path,
            payload,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
            mode=0o600,
        )

    def _disable_after_failure(self, exc: BaseException) -> None:
        with self._lock:
            if self._failed:
                return
            self._failed = True
            self._failure_message = f"{type(exc).__name__}: {exc}"
        logger.warning("Workflow run logging disabled after write failure: %s", exc)


@contextlib.contextmanager
def bind_runlog(session: RunLogSession | None) -> Iterator[RunLogSession | None]:
    if session is None:
        yield None
        return
    if _current_session.get() is session:
        yield session
        return
    session_token = _current_session.set(session)
    span_token = _current_span.set(session.root_span_id)
    try:
        yield session
    finally:
        _current_span.reset(span_token)
        _current_session.reset(session_token)


def open_runlog(
    config: RunLogConfig | None = None,
    *,
    metadata: Mapping[str, Any] | None = None,
) -> RunLogSession:
    return RunLogSession(config, metadata=metadata)


def current_runlog() -> RunLogSession | None:
    session = _current_session.get()
    return session if session is not None and session.enabled else None


def is_enabled() -> bool:
    return current_runlog() is not None


def span(
    kind: str,
    name: str | None = None,
    attributes: Attributes = None,
    *,
    explanation: str | None = None,
    **extra: Any,
) -> Span | _NullSpan:
    session = current_runlog()
    if session is None:
        return _NULL_SPAN
    return session.span(
        kind,
        name,
        attributes,
        explanation=explanation,
        **extra,
    )


def event(
    name: str,
    attributes: Attributes = None,
    *,
    explanation: str | None = None,
    **extra: Any,
) -> None:
    session = current_runlog()
    if session is not None:
        session.event(name, attributes, explanation=explanation, **extra)


def bump(key: str, amount: int = 1) -> None:
    session = current_runlog()
    if session is not None:
        session.bump(key, amount)


def build_run_metadata(
    *,
    argv: list[str] | None = None,
    metis_version: str = "unknown",
    codebase_path: str | None = None,
    config: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    command_argv = list(sys.argv if argv is None else argv)
    cwd = os.getcwd()
    return {
        "argv": _redact_argv(command_argv),
        "command": " ".join(_redact_argv(command_argv)),
        "metis_version": metis_version,
        "config": dict(config or {}),
        "cwd": cwd,
        "codebase_path": codebase_path,
        "git": _git_info(codebase_path or cwd),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "pid": os.getpid(),
        },
    }


def _resolve_paths(
    path_override: str | Path | None,
    run_id: str,
) -> tuple[Path, Path, Path, Path]:
    if path_override is not None:
        requested = Path(path_override).expanduser()
        if requested.suffix.lower() == ".ndjson":
            ndjson = requested.resolve()
            output_dir = ndjson.parent
            meta = ndjson.with_suffix(ndjson.suffix + ".meta.json")
            blobs = ndjson.with_suffix(".blobs")
            return output_dir, ndjson, meta, blobs
        base = requested
    else:
        base = Path("metis-runlog")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = (base / f"{stamp}_{run_id[:6]}").resolve()
    return (
        output_dir,
        output_dir / "run.ndjson",
        output_dir / "meta.json",
        output_dir / "blobs",
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _materialize_attributes(attributes: Attributes) -> Mapping[str, Any]:
    if attributes is None:
        return {}
    if callable(attributes):
        try:
            return dict(attributes())
        except Exception as exc:
            return {"telemetry_attribute_error": f"{type(exc).__name__}: {exc}"}
    return dict(attributes)


def _merge_attributes(
    attributes: Attributes,
    extra: Mapping[str, Any],
) -> Attributes:
    if not extra:
        return attributes
    if callable(attributes):
        return lambda: {**dict(attributes()), **extra}
    return {**dict(attributes or {}), **extra}


def _exception_payload(exc: BaseException) -> dict[str, Any]:
    return {
        "type": type(exc).__name__,
        "message": str(exc),
        "traceback": "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        ),
    }


def _status_rank(status: SpanStatus) -> int:
    return {"ok": 0, "inconclusive": 1, "cancelled": 2, "error": 3}[status]


def _git_info(cwd: str) -> dict[str, Any]:
    def run(*command: str) -> str | None:
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except Exception:
            return None
        return completed.stdout.strip() if completed.returncode == 0 else None

    commit = run("git", "rev-parse", "HEAD")
    if commit is None:
        return {}
    return {
        "commit": commit,
        "branch": run("git", "rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(run("git", "status", "--porcelain")),
    }


def _redact_argv(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    hide_next = False
    for argument in argv:
        if hide_next:
            redacted.append("[REDACTED]")
            hide_next = False
            continue
        lowered = argument.lower().replace("-", "_")
        if argument.startswith("--") and "=" in argument:
            flag, value = argument.split("=", 1)
            if _sensitive_flag(flag):
                redacted.append(f"{flag}=[REDACTED]")
            else:
                redacted.append(f"{flag}={value}")
            continue
        redacted.append(argument)
        if argument.startswith("--") and _sensitive_flag(lowered):
            hide_next = True
    return redacted


def _sensitive_flag(flag: str) -> bool:
    normalized = flag.lower().replace("-", "_")
    return any(
        token in normalized
        for token in (
            "api_key",
            "authorization",
            "credential",
            "password",
            "secret",
            "token",
        )
    )
