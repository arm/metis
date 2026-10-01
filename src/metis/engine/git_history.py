# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import os
import re
import subprocess
from collections.abc import Callable

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

    ``None`` means git is not installed or cannot read the repository, the
    codebase is not in a git checkout, or the checkout has no commit. Use
    ``read_head`` to tell these cases apart.
    """
    try:
        return read_head(codebase_path)
    except GitError as exc:
        logger.warning("Could not read HEAD in %s: %s", codebase_path, exc)
        return None


# git prints this outside a repository. read_head runs git in the C locale, so
# the message is in English.
_NOT_A_REPOSITORY = "not a git repository"


def read_head(codebase_path: str) -> str | None:
    """Return the commit that HEAD names in the codebase.

    Returns ``None`` when the codebase is not in a git checkout, or when the
    checkout has no commit. Raises ``GitError`` when git is missing or fails
    for another reason, for example a repository with dubious ownership. The
    environment is inherited, so GIT_DIR selects a repository that is not under
    the codebase.
    """
    result = _git(
        codebase_path,
        "rev-parse",
        "--verify",
        "--quiet",
        "HEAD^{commit}",
        env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode != 0:
        error = (result.stderr or "").strip()
        if not error or _NOT_A_REPOSITORY in error:
            return None
        raise GitError(f"git rev-parse failed: {_first_line(error)}")
    try:
        return normalize_commit(result.stdout)
    except ValueError:
        return None


_DIFF_TIMEOUT_SECONDS = 600


class GitError(RuntimeError):
    """Raised when git is missing or a git command cannot run."""


def _git(
    codebase_path: str,
    *args: str,
    timeout: int = _GIT_TIMEOUT_SECONDS,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    # Git output can hold bytes that are not UTF-8, for example a diff of a
    # legacy-encoded file. Paths stay quoted ASCII, so replacement is safe.
    try:
        return subprocess.run(
            ["git", *args],
            cwd=codebase_path,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitError(f"git could not run: {exc}") from exc


def is_shallow(codebase_path: str) -> bool:
    result = _git(codebase_path, "rev-parse", "--is-shallow-repository")
    return result.returncode == 0 and result.stdout.strip() == "true"


def has_commit(codebase_path: str, commit: str) -> bool:
    """Return whether the commit object is in the repository."""
    commit = normalize_commit(commit)
    result = _git(codebase_path, "cat-file", "-e", f"{commit}^{{commit}}")
    return result.returncode == 0


def is_ancestor(codebase_path: str, ancestor: str, descendant: str) -> bool:
    ancestor, descendant = normalize_commit(ancestor), normalize_commit(descendant)
    result = _git(codebase_path, "merge-base", "--is-ancestor", ancestor, descendant)
    if result.returncode not in (0, 1):
        raise GitError(f"git merge-base failed: {_first_line(result.stderr)}")
    return result.returncode == 0


def has_tracked_changes(codebase_path: str) -> bool:
    """Return whether tracked files under the codebase differ from HEAD."""
    result = _git(
        codebase_path,
        "--no-optional-locks",
        "status",
        "--porcelain",
        "--untracked-files=no",
        "--",
        ".",
    )
    if result.returncode != 0:
        raise GitError(f"git status failed: {_first_line(result.stderr)}")
    return bool(result.stdout.strip())


def diff_between(codebase_path: str, base: str, head: str) -> str:
    """Return the diff from ``base`` to ``head`` for the files under the codebase.

    Renames are reported as a delete and an add. ``--relative`` limits the diff
    to the codebase directory and makes its paths relative to it, so they match
    the paths that ``index`` stored when the codebase is a subdirectory.
    """
    base, head = normalize_commit(base), normalize_commit(head)
    result = _git(
        codebase_path,
        "-c",
        "core.quotePath=true",
        "diff",
        "--no-renames",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--relative",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        base,
        head,
        timeout=_DIFF_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise GitError(f"git diff failed: {_first_line(result.stderr)}")
    return result.stdout


_FETCH_TIMEOUT_SECONDS = 600
_DEEPEN_STEPS = (50, 500, 5000)


def deepen_until(codebase_path: str, done: Callable[[], bool]) -> bool:
    """Fetch more history of a shallow clone until ``done()`` is true.

    Runs ``git fetch --deepen`` in growing steps, then ``git fetch --unshallow``.
    Returns ``done()`` after the last fetch. Raises ``GitError`` when a fetch
    fails, for example without network access or credentials.
    """
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    for depth in _DEEPEN_STEPS:
        if not is_shallow(codebase_path):
            return done()
        _fetch(codebase_path, env, f"--deepen={depth}")
        if done():
            return True
    if is_shallow(codebase_path):
        _fetch(codebase_path, env, "--unshallow")
    return done()


def _fetch(codebase_path: str, env: dict[str, str], option: str) -> None:
    result = _git(
        codebase_path, "fetch", option, timeout=_FETCH_TIMEOUT_SECONDS, env=env
    )
    if result.returncode != 0:
        raise GitError(f"git fetch {option} failed: {_first_line(result.stderr)}")


def _first_line(text: str) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[0] if lines else "no error output"
