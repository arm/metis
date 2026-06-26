# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any


def stable_json_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def input_fingerprint(value: Any) -> str:
    return stable_json_hash(value)


def file_fingerprint(path: str | Path) -> str:
    target = Path(path)
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_fingerprint(repo_root: str | Path) -> str:
    root = Path(repo_root).resolve()
    head = _git_output(root, "rev-parse", "HEAD")
    if head:
        return f"git:{head}"
    return f"nogit:{stable_json_hash(str(root))}"


def _git_output(cwd: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None
