# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


def write_json_atomic(
    path: str | Path,
    payload: object,
    *,
    indent: int,
    ensure_ascii: bool = True,
    allow_nan: bool = True,
    mode: int | None = None,
) -> None:
    target = Path(path)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(
                payload,
                handle,
                indent=indent,
                ensure_ascii=ensure_ascii,
                allow_nan=allow_nan,
            )
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            temporary.chmod(mode)
        os.replace(temporary, target)
        if mode is not None:
            target.chmod(mode)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
