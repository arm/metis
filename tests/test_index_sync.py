# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from metis.cli import commands
from metis.cli.command_runtime import CommandRuntime
from metis.engine import git_history
from metis.engine.capabilities.indexing import SyncResult
from metis.exceptions import IndexSyncError
from test_indexing_updates import _Indexes

requires_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

UNKNOWN_SHA = "0123456789abcdef0123456789abcdef01234567"


def git(cwd, *args):
    config = ["-c", "user.name=t", "-c", "user.email=t@example.com"]
    config += ["-c", "protocol.file.allow=always"]
    result = subprocess.run(
        ["git", *config, *args], cwd=cwd, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def commit_file(repo, name, content):
    path = Path(repo) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode())
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", f"change {name}")
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def remote(tmp_path):
    """A repository with four commits: c1 c2 c3 c4."""
    path = tmp_path / "remote"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    commits = [
        commit_file(path, "a.c", "int a;\n"),
        commit_file(path, "b.c", "int b;\n"),
        commit_file(path, "a.c", "int a2;\n"),
        commit_file(path, "c.c", "int c;\n"),
    ]
    return SimpleNamespace(path=path, commits=commits)


@pytest.fixture
def sync(engine, dummy_backend, monkeypatch):
    """Run sync on a codebase with a mocked index update."""
    apply_patch = Mock()
    monkeypatch.setattr(engine.indexing, "_apply_patch", apply_patch)

    def run(codebase, recorded, explicit_commit=None, **flags):
        engine._config.codebase_path = str(codebase)
        engine._config.index_commit = explicit_commit
        dummy_backend.get_index_state.return_value = (
            {"commit": recorded} if recorded else None
        )
        return engine.indexing.sync_index(**flags)

    def recorded():
        (state,), _ = dummy_backend.set_index_state.call_args
        assert state["operation"] == "sync"
        return state["commit"]

    def assert_nothing_changed():
        apply_patch.assert_not_called()
        dummy_backend.set_index_state.assert_not_called()

    return SimpleNamespace(
        run=run,
        apply=apply_patch,
        backend=dummy_backend,
        recorded=recorded,
        assert_nothing_changed=assert_nothing_changed,
    )


@requires_git
def test_sync_applies_the_range_and_records_the_new_commit(remote, sync):
    c1, c2, c3, c4 = remote.commits

    assert sync.run(remote.path, c2) == SyncResult("updated", c2, c4)

    (patch,), _ = sync.apply.call_args
    assert "a.c" in patch and "c.c" in patch and "b.c" not in patch
    assert sync.recorded() == c4


@requires_git
def test_sync_is_a_no_op_when_the_index_is_up_to_date(remote, sync):
    assert sync.run(remote.path, remote.commits[-1]).status == "up_to_date"
    sync.assert_nothing_changed()


@requires_git
@pytest.mark.parametrize(
    ("recorded", "message"),
    [
        (None, "Run `index` first"),
        ("main", "not a valid commit id"),
        ("--upload-pack=touch x", "not a valid commit id"),
        ("a" * 39, "not a valid commit id"),
        (UNKNOWN_SHA, "is not in this repository"),
    ],
    ids=["no-record", "branch-name", "option", "short-id", "missing-commit"],
)
def test_sync_refuses_a_recorded_commit_it_cannot_use(remote, sync, recorded, message):
    with pytest.raises(IndexSyncError, match=message):
        sync.run(remote.path, recorded)
    sync.assert_nothing_changed()


def test_sync_outside_a_git_checkout_asks_for_one(tmp_path, sync):
    with pytest.raises(IndexSyncError, match="needs the git checkout"):
        sync.run(tmp_path, UNKNOWN_SHA)


def side_branch(remote, _tmp_path):
    git(remote.path, "checkout", "-q", "-b", "side", remote.commits[1])
    side = commit_file(remote.path, "side.c", "int side;\n")
    git(remote.path, "checkout", "-q", "main")
    return remote.path, side


def shallow_clone(remote, tmp_path, fetch=None):
    git(tmp_path, "clone", "-q", "--depth", "1", f"file://{remote.path}", "clone")
    if fetch:
        git(tmp_path / "clone", "fetch", "-q", "--depth", "1", "origin", fetch)
    return tmp_path / "clone"


def shallow_without_c2(remote, tmp_path):
    return shallow_clone(remote, tmp_path), remote.commits[1]


def shallow_with_c2(remote, tmp_path):
    return shallow_clone(remote, tmp_path, fetch=remote.commits[1]), remote.commits[1]


ALLOW = {"allow_non_ancestor": True}
RANGE_CASES = [
    pytest.param(side_branch, {}, "is not an ancestor of", id="non-ancestor"),
    pytest.param(side_branch, ALLOW, None, id="non-ancestor-allowed"),
    pytest.param(shallow_without_c2, {}, "--unshallow", id="shallow-missing"),
    pytest.param(shallow_with_c2, {}, "does not show that", id="shallow-no-ancestry"),
    pytest.param(shallow_with_c2, ALLOW, None, id="shallow-allowed"),
]


@requires_git
@pytest.mark.parametrize(("prepare", "flags", "error"), RANGE_CASES)
def test_sync_checks_the_history_between_the_commits(
    remote, tmp_path, sync, prepare, flags, error
):
    path, recorded = prepare(remote, tmp_path)

    if error:
        with pytest.raises(IndexSyncError, match=error):
            sync.run(path, recorded, **flags)
        sync.assert_nothing_changed()
    else:
        assert sync.run(path, recorded, **flags).status == "updated"
        assert sync.recorded() == remote.commits[-1]


@requires_git
def test_sync_decodes_diff_bytes_that_are_not_utf8(remote, sync):
    base = commit_file(remote.path, "legacy.c", b'char *s = "caf\xe9";\n')
    commit_file(remote.path, "legacy.c", b'char *s = "na\xefve";\n')

    assert sync.run(remote.path, base).status == "updated"
    (patch,), _ = sync.apply.call_args
    assert "�" in patch


@requires_git
@pytest.mark.parametrize(
    ("recorded", "explicit"), [(0, 2), (0, 0)], ids=["behind-head", "already-recorded"]
)
def test_sync_requires_head_to_be_the_explicit_commit(remote, sync, recorded, explicit):
    commits = remote.commits
    expected = f"HEAD is {commits[-1]}, not {commits[explicit]}"

    with pytest.raises(IndexSyncError, match=expected):
        sync.run(remote.path, commits[recorded], explicit_commit=commits[explicit])
    sync.assert_nothing_changed()


@requires_git
def test_sync_refuses_uncommitted_changes_to_tracked_files(remote, sync):
    (remote.path / "a.c").write_text("int dirty;\n")

    with pytest.raises(IndexSyncError, match="uncommitted changes"):
        sync.run(remote.path, remote.commits[1])
    sync.assert_nothing_changed()


@requires_git
def test_tracked_changes_are_checked_only_under_the_codebase(remote):
    commit_file(remote.path, "lib/x.c", "int x;\n")
    (remote.path / "a.c").write_text("int dirty_outside;\n")
    assert not git_history.has_tracked_changes(str(remote.path / "lib"))

    (remote.path / "lib" / "x.c").write_text("int dirty_inside;\n")
    assert git_history.has_tracked_changes(str(remote.path / "lib"))


@requires_git
def test_sync_does_not_record_a_commit_when_head_moves_during_the_update(remote, sync):
    sync.apply.side_effect = lambda _patch: commit_file(remote.path, "d.c", "int d;")

    with pytest.raises(IndexSyncError, match="checkout changed while sync ran"):
        sync.run(remote.path, remote.commits[1])
    sync.backend.set_index_state.assert_not_called()


def test_sync_reports_missing_git(monkeypatch, tmp_path, sync):
    no_git = Mock(side_effect=FileNotFoundError("git"))
    monkeypatch.setattr(git_history.subprocess, "run", no_git)

    with pytest.raises(IndexSyncError, match="git could not run"):
        sync.run(tmp_path, UNKNOWN_SHA)


def test_sync_reports_a_git_error_that_is_not_a_missing_checkout(
    monkeypatch, tmp_path, sync
):
    refused = subprocess.CompletedProcess(
        [], 128, stdout="", stderr="fatal: detected dubious ownership in repository\n"
    )
    monkeypatch.setattr(git_history.subprocess, "run", Mock(return_value=refused))

    with pytest.raises(IndexSyncError, match="dubious ownership in repository"):
        sync.run(tmp_path, UNKNOWN_SHA)
    sync.assert_nothing_changed()


@requires_git
def test_read_head_reports_a_repository_that_git_cannot_read(remote):
    (remote.path / ".git" / "config").write_text("[broken\n")

    with pytest.raises(git_history.GitError, match="bad config"):
        git_history.read_head(str(remote.path))
    assert git_history.head_commit(str(remote.path)) is None


@requires_git
def test_sync_updates_real_index_rows_for_a_subdirectory_codebase(
    remote, engine, dummy_backend
):
    lib = remote.path / "lib"
    for name in ("keep.c", "edit.c", "gone.c"):
        commit_file(remote.path, f"lib/{name}", f"int {name[:-2]};\n")
    base = commit_file(remote.path, "lib/old.c", "int old;\n")
    engine._config.codebase_path = str(lib)
    engine._config.index_commit = None
    idx = _Indexes(engine, dummy_backend)
    for name in ("keep.c", "edit.c", "gone.c", "old.c"):
        idx.seed(name)
    idx.code_index.insert_nodes = Mock(wraps=idx.code_index.insert_nodes)
    (lib / "edit.c").write_text("int edited;\n")
    git(remote.path, "rm", "-q", "lib/gone.c")
    git(remote.path, "mv", "lib/old.c", "lib/new.c")
    head = commit_file(remote.path, "outside.c", "int outside;\n")
    dummy_backend.get_index_state.return_value = {"commit": base}

    assert engine.indexing.sync_index() == SyncResult("updated", base, head)

    assert idx.code_rows() == {"keep.c", "edit.c", "new.c"}
    written = {
        node.metadata["file_name"]: node.get_content()
        for call in idx.code_index.insert_nodes.call_args_list
        for node in call.args[0]
    }
    assert written == {"edit.c": "int edited;", "new.c": "int old;"}
    (state,), _ = dummy_backend.set_index_state.call_args
    assert (state["commit"], state["operation"]) == (head, "sync")


def test_sync_command_passes_the_flags_and_reports_the_result(monkeypatch):
    printed = []
    monkeypatch.setattr(
        commands, "print_console", lambda msg, *_a, **_k: printed.append(msg)
    )
    sync_index = Mock(return_value=SyncResult("updated", "a" * 40, "b" * 40))
    engine = SimpleNamespace(indexing=SimpleNamespace(sync_index=sync_index))
    args = SimpleNamespace(quiet=True, allow_non_ancestor=True)

    commands.run_sync(engine, args, CommandRuntime("sync", []))

    sync_index.assert_called_once_with(allow_non_ancestor=True)
    assert f"from {'a' * 40} to {'b' * 40}" in "\n".join(printed)
