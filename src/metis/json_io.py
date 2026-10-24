# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import math
import os
import re
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from typing import TextIO


def json_object_from_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("JSON contains a duplicate mapping key")
        value[key] = item
    return value


def parse_json_object(data: bytes) -> dict[str, Any]:
    if not isinstance(data, bytes):
        raise TypeError("JSON data must be bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        raise ValueError("JSON must not contain a UTF-8 byte order mark")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("JSON must be valid UTF-8") from None

    def reject_constant(_value):
        raise ValueError("JSON contains a non-finite number")

    try:
        payload = json.loads(
            text,
            object_pairs_hook=json_object_from_pairs,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("Input must contain exactly one valid JSON document") from None
    if not isinstance(payload, dict):
        raise ValueError("JSON payload must be an object")
    validate_json_tree(payload)
    return payload


def load_json_object_file(path: str | Path) -> dict[str, Any]:
    """Load a strict JSON object without file-size or collection-size caps."""
    return parse_json_object(Path(path).read_bytes())


def validate_json_tree(payload: object) -> None:
    stack: list[tuple[Iterator[Any], int | None]] = [(iter((payload,)), None)]
    ancestors: set[int] = set()
    while stack:
        values, container_id = stack[-1]
        try:
            value = next(values)
        except StopIteration:
            stack.pop()
            if container_id is not None:
                ancestors.remove(container_id)
            continue
        if isinstance(value, dict):
            for key in value:
                if type(key) is not str:
                    raise ValueError("JSON mapping keys must be strings")
                _validate_string(key)
            children = iter(value.values())
        elif isinstance(value, list):
            children = iter(value)
        else:
            if type(value) is str:
                _validate_string(value)
            elif type(value) is float:
                if not math.isfinite(value):
                    raise ValueError("JSON contains a non-finite number")
            elif value is not None and type(value) not in {bool, int}:
                raise ValueError("JSON payload must contain only JSON values")
            continue
        identity = id(value)
        if identity in ancestors:
            raise ValueError("JSON contains a recursive container")
        ancestors.add(identity)
        stack.append((children, identity))


def _validate_string(value: str) -> None:
    if not value.isascii() and re.search(r"[\ud800-\udfff]", value):
        raise ValueError("JSON strings must contain Unicode scalar values")


def write_json_atomic(
    path: str | Path,
    payload: object,
    *,
    indent: int,
    ensure_ascii: bool = True,
    allow_nan: bool = False,
    mode: int | None = None,
) -> None:
    with atomic_text_writer(path, mode=0o600 if mode is None else mode) as handle:
        json.dump(
            payload,
            handle,
            indent=indent,
            ensure_ascii=ensure_ascii,
            allow_nan=allow_nan,
        )


@contextmanager
def atomic_text_writer(
    path: str | Path, *, mode: int | None = None, newline: str | None = None
) -> Iterator[TextIO]:
    """Replace a text output only after its complete contents reach disk."""
    target = Path(path)
    target.parent.stat()
    target = target.parent.resolve() / target.name
    if mode is None:
        try:
            mode = stat.S_IMODE(target.stat().st_mode)
        except FileNotFoundError:
            pass
    with tempfile.TemporaryDirectory(
        dir=target.parent, prefix=".metis-", suffix=".tmp"
    ) as directory:
        temporary_directory = Path(directory)
        temporary_directory.chmod(0o700)
        temporary = temporary_directory / "report"
        with temporary.open("w", encoding="utf-8", newline=newline) as handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            temporary.chmod(mode)
        os.replace(temporary, target)
