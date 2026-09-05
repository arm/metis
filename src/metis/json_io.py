# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO


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
