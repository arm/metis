# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import math
import os
import tempfile
from collections.abc import Mapping
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from .schema import PREVIEW_CHARS
from .schema import RunLogConfig

_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "aws_secret_access_key",
        "aws_session_token",
        "client_secret",
        "cookie",
        "credentials",
        "password",
        "pg_password",
        "private_key",
        "proxy_authorization",
        "refresh_token",
        "secret",
        "secret_access_key",
        "session_token",
        "set_cookie",
        "token",
        "x_api_key",
    }
)
_SENSITIVE_SUFFIXES = (
    "_access_key",
    "_api_key",
    "_authorization",
    "_client_secret",
    "_cookie",
    "_credentials",
    "_password",
    "_private_key",
    "_secret",
    "_secret_access_key",
    "_session_token",
    "_token",
)


class PayloadEncoder:
    """Converts trace payloads into bounded JSON values and blob references."""

    def __init__(self, blobs_dir: Path, config: RunLogConfig) -> None:
        self._blobs_dir = blobs_dir
        self._config = config

    def encode_mapping(self, value: Mapping[str, Any] | None) -> dict[str, Any]:
        if not value:
            return {}
        seen: set[int] = set()
        return {
            str(key): self._encode(item, key=str(key), depth=0, seen=seen)
            for key, item in value.items()
        }

    def _encode(
        self,
        value: Any,
        *,
        key: str | None,
        depth: int,
        seen: set[int],
    ) -> Any:
        if key is not None and _is_sensitive_key(key):
            return _redacted(value)
        if depth >= self._config.max_depth:
            return {"$truncated": "max_depth", "type": type(value).__name__}
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else repr(value)
        if isinstance(value, str):
            return self._encode_text(value)
        if isinstance(value, bytes):
            return self._encode_bytes(value)
        if isinstance(value, (Path, datetime, date)):
            return str(value)
        if isinstance(value, Enum):
            return self._encode(value.value, key=key, depth=depth + 1, seen=seen)

        identity = id(value)
        if identity in seen:
            return {"$truncated": "cycle", "type": type(value).__name__}
        seen.add(identity)
        try:
            normalized = self._normalize_object(value)
            if normalized is not value:
                return self._encode(
                    normalized,
                    key=key,
                    depth=depth + 1,
                    seen=seen,
                )
            if isinstance(value, Mapping):
                encoded = {
                    str(child_key): self._encode(
                        child_value,
                        key=str(child_key),
                        depth=depth + 1,
                        seen=seen,
                    )
                    for child_key, child_value in _limited_items(
                        value.items(), self._config.max_collection_items
                    )
                }
                if len(value) > self._config.max_collection_items:
                    encoded["$truncated_items"] = (
                        len(value) - self._config.max_collection_items
                    )
                return self._maybe_spill_json(encoded)
            if isinstance(value, (list, tuple, set, frozenset)):
                source = list(value)
                encoded_items = [
                    self._encode(item, key=None, depth=depth + 1, seen=seen)
                    for item in source[: self._config.max_collection_items]
                ]
                if isinstance(value, (set, frozenset)):
                    encoded_items.sort(key=_stable_sort_key)
                if len(source) > self._config.max_collection_items:
                    encoded_items.append(
                        {
                            "$truncated_items": len(source)
                            - self._config.max_collection_items
                        }
                    )
                return self._maybe_spill_json(encoded_items)
            return self._encode_text(_safe_repr(value))
        finally:
            seen.discard(identity)

    def _normalize_object(self, value: Any) -> Any:
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            return {
                field.name: getattr(value, field.name)
                for field in dataclasses.fields(value)
            }
        model_dump = getattr(value, "model_dump", None)
        if callable(model_dump):
            try:
                return model_dump(mode="json", by_alias=True)
            except TypeError:
                try:
                    return model_dump()
                except Exception:
                    return value
            except Exception:
                return value
        return value

    def _encode_text(self, text: str) -> Any:
        raw = text.encode("utf-8")
        if len(raw) <= self._config.blob_threshold:
            return text
        return self._blob_reference(
            raw,
            extension="txt",
            media_type="text/plain; charset=utf-8",
            preview=text[:PREVIEW_CHARS],
        )

    def _encode_bytes(self, raw: bytes) -> Any:
        if len(raw) <= self._config.blob_threshold:
            return {
                "$bytes": base64.b64encode(raw).decode("ascii"),
                "bytes": len(raw),
                "encoding": "base64",
            }
        return self._blob_reference(
            raw,
            extension="bin",
            media_type="application/octet-stream",
            preview=base64.b64encode(raw[:48]).decode("ascii"),
        )

    def _maybe_spill_json(self, value: Any) -> Any:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(raw) <= self._config.blob_threshold:
            return value
        preview = raw[:PREVIEW_CHARS].decode("utf-8", errors="replace")
        return self._blob_reference(
            raw,
            extension="json",
            media_type="application/json",
            preview=preview,
        )

    def _blob_reference(
        self,
        raw: bytes,
        *,
        extension: str,
        media_type: str,
        preview: str,
    ) -> dict[str, Any]:
        digest = hashlib.sha256(raw).hexdigest()
        reference: dict[str, Any] = {
            "bytes": len(raw),
            "sha256": digest,
            "media_type": media_type,
            "preview": preview,
        }
        if self._config.content == "metadata":
            reference["$omitted"] = True
            return reference
        self._blobs_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self._blobs_dir / f"{digest}.{extension}"
        if not path.exists():
            fd, temporary = tempfile.mkstemp(
                dir=self._blobs_dir,
                prefix=f".{digest}.",
                suffix=".tmp",
            )
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
                path.chmod(0o600)
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                Path(temporary).unlink(missing_ok=True)
                raise
        reference["$ref"] = path.relative_to(self._blobs_dir.parent).as_posix()
        return reference


def _limited_items(items: Any, limit: int) -> list[tuple[Any, Any]]:
    result: list[tuple[Any, Any]] = []
    for index, item in enumerate(items):
        if index >= limit:
            break
        result.append(item)
    return result


def _is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    return normalized in _SENSITIVE_KEYS or normalized.endswith(_SENSITIVE_SUFFIXES)


def _redacted(value: Any) -> dict[str, Any]:
    raw = _redaction_bytes(value)
    return {"$redacted": True, "sha256": hashlib.sha256(raw).hexdigest()}


def _redaction_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    try:
        return json.dumps(value, sort_keys=True, default=_safe_repr).encode("utf-8")
    except Exception:
        return _safe_repr(value).encode("utf-8")


def _safe_repr(value: Any) -> str:
    try:
        return repr(value)
    except Exception:
        return f"<unrepresentable {type(value).__name__}>"


def _stable_sort_key(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    except Exception:
        return _safe_repr(value)
