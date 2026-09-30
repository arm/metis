# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import re
import subprocess

logger = logging.getLogger("metis")

_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_GIT_TIMEOUT_SECONDS = 30


def normalize_commit(value: object) -> str:
    """Return a full lowercase commit id, or raise ``ValueError``.

    Only a full SHA-1 or SHA-256 id is accepted. A branch name or a short id can
    move or be ambiguous, and it would then describe a different commit later.
    """
    commit = str(value or "").strip().lower()
    if not _COMMIT_PATTERN.fullmatch(commit):
        raise ValueError("A commit must be a full 40 or 64 character hexadecimal id")
    return commit


def head_commit(codebase_path: str) -> str | None:
    """Return the commit that HEAD names in the codebase, or ``None``.

    ``None`` means git is not installed, the codebase is not in a git checkout,
    or the checkout has no commit. The environment is inherited, so GIT_DIR
    selects a repository that is not under the codebase.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", "HEAD^{commit}"],
            cwd=codebase_path,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Could not run git in %s: %s", codebase_path, exc)
        return None
    if result.returncode != 0:
        return None
    try:
        return normalize_commit(result.stdout)
    except ValueError:
        return None
