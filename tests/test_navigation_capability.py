# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import ThreadPoolExecutor
import pytest
import subprocess
from threading import Barrier
from threading import BrokenBarrierError
from threading import Lock

from metis.engine.capabilities.navigation import NavigationCapability


def _build_runner(tmp_path):
    runner = NavigationCapability(
        codebase_path=str(tmp_path), timeout_seconds=8, max_chars=16000
    )
    runner._has_grep = False
    runner._has_find = False
    return runner


def test_cat_emits_numbered_lines(tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("line1\nline2\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.cat("a.txt")
    assert out == "1: line1\n2: line2"


def test_sed_emits_numbered_slice(tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("a\nb\nc\nd\ne\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.sed("a.txt", 2, 4)
    assert out == "2: b\n3: c\n4: d"


def test_sed_clamps_past_eof(tmp_path):
    source = tmp_path / "a.txt"
    source.write_text("a\nb\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    assert runner.sed("a.txt", 1, 100) == "1: a\n2: b"


def test_cat_missing_file_raises(tmp_path):
    runner = _build_runner(tmp_path)
    with pytest.raises(FileNotFoundError):
        runner.cat("nope.txt")


def test_find_name_fallback_finds_matching_files(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "target.c").write_text("x", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "target.c").write_text("y", encoding="utf-8")
    (tmp_path / "lib" / "other.c").write_text("z", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.find_name("target.c")
    assert out == ["lib/target.c", "src/target.c"]


def test_grep_fallback_searches_recursively(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("alpha\nbeta\n", encoding="utf-8")
    (tmp_path / "src" / "b.c").write_text("gamma\nbeta42\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.grep(r"beta", "src")
    lines = out.splitlines()
    assert "src/a.c:2:beta" in lines
    assert "src/b.c:2:beta42" in lines


def test_grep_fallback_invalid_pattern_raises(tmp_path):
    (tmp_path / "x.txt").write_text("hello\n", encoding="utf-8")
    runner = _build_runner(tmp_path)
    with pytest.raises(ValueError, match="Invalid grep pattern"):
        runner.grep("(", ".")


def test_grep_can_force_python_regex_even_when_shell_grep_exists(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("foo\t(\n", encoding="utf-8")

    runner = NavigationCapability(
        codebase_path=str(tmp_path), timeout_seconds=8, max_chars=16000
    )
    runner._has_grep = False

    def _unexpected_run(*args, **kwargs):
        raise AssertionError("shell grep should not run when _has_grep=False")

    monkeypatch.setattr(subprocess, "run", _unexpected_run)

    out = runner.grep(r"foo[[:space:]]*\(", "src")

    assert out.splitlines() == ["src/a.c:1:foo\t("]


@pytest.mark.parametrize(
    ("filename", "absolute_path", "expected_path"),
    [("a.c", False, "a.c"), ("src/a.c", True, "src/a.c"), ("-", False, "./-")],
)
def test_shell_grep_returns_relative_file_and_line(
    tmp_path, absolute_path, filename, expected_path
):
    source = tmp_path / filename
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("alpha\nbeta\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    runner._has_grep = True

    out = runner.grep("beta", str(source) if absolute_path else filename)

    assert out == f"{expected_path}:2:beta"
    assert runner.grep("beta", ".") == f"./{filename}:2:beta"


def test_shell_navigation_serializes_subprocesses(tmp_path, monkeypatch):
    runner = NavigationCapability(
        codebase_path=str(tmp_path), timeout_seconds=8, max_chars=16000
    )
    runner._has_grep = True
    rendezvous = Barrier(2)
    state_lock = Lock()
    active = 0
    peak = 0

    def run(argv, **_kwargs):
        nonlocal active, peak
        with state_lock:
            active += 1
            peak = max(peak, active)
        try:
            rendezvous.wait(timeout=0.2)
        except BrokenBarrierError:
            pass
        with state_lock:
            active -= 1
        return subprocess.CompletedProcess(argv, 0, stdout="match", stderr="")

    monkeypatch.setattr(subprocess, "run", run)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _index: runner.grep("x", "."), range(2)))

    assert results == ("match", "match")
    assert peak == 1


@pytest.mark.parametrize("separator", ["\u2028", "\u2029", "\x85", "\v", "\f"])
def test_navigation_uses_canonical_source_lines(tmp_path, separator):
    (tmp_path / "input.txt").write_text(
        f"first{separator}fragment\nsecond\n", encoding="utf-8"
    )
    runner = _build_runner(tmp_path)
    assert runner.cat("input.txt") == f"1: first{separator}fragment\n2: second"
    assert runner.sed("input.txt", 2, 2) == "2: second"
    assert runner.grep("second", "input.txt") == "input.txt:2:second"


@pytest.mark.parametrize("native_grep", [False, True])
def test_recursive_navigation_stays_inside_codebase(tmp_path, native_grep):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.c").write_text("secret\n", encoding="utf-8")
    (repo / "safe.c").write_text("safe\n", encoding="utf-8")
    (repo / "leaked.c").symlink_to(outside / "secret.c")
    (repo / "linked-dir").symlink_to(outside, target_is_directory=True)
    runner = _build_runner(repo)
    runner._has_grep = native_grep

    assert runner.grep("secret", ".") == ""
    assert runner.find_name("secret.c") == []
    with pytest.raises(ValueError, match="Path escapes codebase"):
        runner.cat("leaked.c")
    with pytest.raises(ValueError, match="Path escapes codebase"):
        runner.grep("secret", "leaked.c")
