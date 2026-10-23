# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import pytest
import shutil
import sqlite3
import subprocess
import sys
from threading import Barrier
from threading import BrokenBarrierError
from threading import Lock
from time import monotonic

from metis.engine.capabilities.navigation import NavigationCapability
from metis.engine.capabilities.catalog import get_capability_manifest
from metis.engine.tools.navigation import navigation_model_tools
from metis.cli.utils import save_output


def _build_runner(tmp_path):
    runner = NavigationCapability(
        codebase_path=str(tmp_path), timeout_seconds=8, max_chars=16000
    )
    runner._has_grep = False
    runner._has_find = False
    return runner


@pytest.mark.parametrize(
    ("grep_kind", "find_kind"),
    (
        ("native", "native"),
        ("native", "missing"),
        ("missing", "native"),
        ("missing", "missing"),
        ("limited", "native"),
        ("native", "limited"),
        ("limited", "limited"),
    ),
)
def test_navigation_handles_missing_or_limited_native_tools(
    tmp_path, monkeypatch, grep_kind, find_kind
):
    native = {name: shutil.which(name) for name in ("grep", "find")}
    if not all(native.values()):
        pytest.skip("Native grep and find are needed to build the tool matrix")
    root = tmp_path / "repository"
    root.mkdir()
    source = root / "target[1] ü.c"
    source.write_text("first line\nneedle\tvalue\n", encoding="utf-8")
    (root / "line\nbreak.c").write_text("other\n", encoding="utf-8")
    (root / "target1 ü.c").write_text("other\n", encoding="utf-8")
    save_output(
        [root / "report.json"],
        {"reviews": [{"file": source.name, "reviews": [{"issue": "needle report"}]}]},
        quiet=True,
        codebase_path=root,
    )
    (root / ".metis" / "hidden.c").write_text("needle state\n", encoding="utf-8")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    for name, kind in (("grep", grep_kind), ("find", find_kind)):
        executable = binaries / name
        if kind == "native":
            executable.symlink_to(native[name])
        elif kind == "limited":
            executable.write_text(
                f"#!{sys.executable}\nimport os\nimport sys\n"
                "if any(arg.startswith('--exclude') or arg == '-samefile' for arg in sys.argv[1:]):\n"
                "    sys.stderr.write('unsupported option\\n')\n    sys.exit(2)\n"
                f"os.execv({native[name]!r}, [{name!r}, *sys.argv[1:]])\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(binaries))
    runner = NavigationCapability(
        codebase_path=str(root), timeout_seconds=8, max_chars=16000
    )
    for name, kind in (("grep", grep_kind), ("find", find_kind)):
        if kind != "native":
            assert not getattr(runner, f"_has_{name}")
    for target in (source.name, "."):
        assert (
            runner.grep(r"needle[[:space:]]+value", target).removeprefix("./")
            == f"{source.name}:2:needle\tvalue"
        )
    assert runner.grep("absent", ".") == ""
    assert runner.find_name(source.name) == [source.name]
    assert runner.find_name("line\nbreak.c") == ["line\nbreak.c"]
    assert runner.find_name("hidden.c") == []
    assert runner.find_name("report.json") == []
    assert runner.cat(source.name) == "1: first line\n2: needle\tvalue"
    assert runner.sed(source.name, 2, 2) == "2: needle\tvalue"


def test_manifest_navigation_tools_bind_operations_and_copy_schemas(tmp_path):
    (tmp_path / "source.c").write_text("int value;\n", encoding="utf-8")
    runner = _build_runner(tmp_path)
    manifest = get_capability_manifest("navigation")
    cat = next(
        operation for operation in manifest.operations if operation.name == "cat"
    )
    manifest = replace(
        manifest,
        operations=(
            replace(cat, name="read_source"),
            replace(cat, name="missing", operation="missing", status="inactive"),
            replace(
                cat, name="hidden", operation="missing", surfaces=("orchestration",)
            ),
        ),
    )
    tools = navigation_model_tools(runner, manifest, max_contract_chars=123)
    assert [tool.name for tool in tools] == ["read_source"]
    tool = tools[0]
    assert tool.description == cat.description
    assert tool.metadata["metis_contract_max_chars"] == 123
    assert tool.metadata["metis_contract"]
    assert tool.invoke({"path": "source.c"}) == "1: int value;"
    tool.args_schema["properties"]["path"]["description"] = "changed"
    assert cat.input_schema["properties"]["path"]["description"] != "changed"
    assert (
        navigation_model_tools(
            runner, replace(manifest, status="inactive"), max_contract_chars=123
        )
        == ()
    )


@pytest.mark.parametrize("path", ["a.txt", "./~/a.txt", "./~metis-no-such-user/a.txt"])
def test_cat_emits_numbered_lines(tmp_path, path):
    source = tmp_path / path
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("line1\nline2\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    out = runner.cat(path)
    assert out == "1: line1\n2: line2"


@pytest.mark.parametrize(
    ("text", "start", "end", "expected"),
    [
        ("a\nb\nc\nd\ne\n", 2, 4, "2: b\n3: c\n4: d"),
        ("before\n\nafter\n", 2, 2, "2: "),
        ("before\n\nafter\n", 1, 2, "1: before\n2: "),
    ],
)
def test_sed_emits_numbered_slice(tmp_path, text, start, end, expected):
    source = tmp_path / "a.txt"
    source.write_text(text, encoding="utf-8")

    runner = _build_runner(tmp_path)
    assert runner.sed("a.txt", start, end) == expected


@pytest.mark.parametrize("end", [100, 10**30])
def test_sed_clamps_past_eof(tmp_path, end):
    source = tmp_path / "a.txt"
    source.write_text("a\nb\n", encoding="utf-8")

    runner = _build_runner(tmp_path)
    assert runner.sed("a.txt", 1, end) == "1: a\n2: b"
    assert runner.sed("a.txt", end, end) == ""


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


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("unavailable", ["file", "directory", "missing"])
def test_search_failures_are_not_empty_evidence(tmp_path, native, unavailable):
    directory = tmp_path / "src"
    directory.mkdir()
    source = directory / "target.c"
    source.write_text("needle\n", encoding="utf-8")
    runner = _build_runner(tmp_path)
    runner._has_grep = runner._has_find = native
    assert runner.grep("absent", ".") == ""
    assert runner.find_name("absent.c") == []
    if unavailable == "missing":
        with pytest.raises(RuntimeError, match="No such file"):
            runner.grep("needle", "missing")
        return

    blocked = source if unavailable == "file" else directory
    original_mode = blocked.stat().st_mode
    try:
        blocked.chmod(0)
        try:
            if unavailable == "file":
                blocked.read_text()
            else:
                list(blocked.iterdir())
        except PermissionError:
            pass
        else:
            pytest.skip("Filesystem permissions do not prevent reading")
        with pytest.raises(RuntimeError, match="Permission denied"):
            runner.grep("needle", ".")
        if unavailable == "directory":
            with pytest.raises(RuntimeError, match="Permission denied"):
                runner.find_name("target.c")
        else:
            assert runner.find_name("target.c") == ["src/target.c"]
    finally:
        blocked.chmod(original_mode)

    assert "target.c:1:needle" in runner.grep("needle", ".")
    assert runner.find_name("target.c") == ["src/target.c"]


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

    commands = []
    popen = subprocess.Popen

    def record_process(argv, **kwargs):
        commands.append(argv)
        return popen(argv, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", record_process)

    out = runner.grep(r"foo[[:space:]]*\(", "src")

    assert out.splitlines() == ["src/a.c:1:foo\t("]
    assert commands[0][0] == sys.executable


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

    class Process:
        returncode = 0

        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def communicate(self, **_kwargs):
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
            return "match", ""

    monkeypatch.setattr(subprocess, "Popen", Process)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _index: runner.grep("x", "."), range(2)))

    assert results == ("match", "match")
    assert peak == 1


def test_navigation_timeout_includes_serialization_wait(tmp_path):
    runner = _build_runner(tmp_path)
    runner._has_grep = True
    runner.timeout_seconds = 0.1
    runner._subprocess_lock.acquire()
    start = monotonic()
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            runner.grep("x", ".")
    finally:
        runner._subprocess_lock.release()
    assert monotonic() - start < 2


@pytest.mark.parametrize("operation", ["grep", "find_name", "cat"])
def test_navigation_registry_lock_obeys_configured_timeout(
    tmp_path, monkeypatch, operation
):
    source = tmp_path / "source.c"
    source.write_text("needle source\n", encoding="utf-8")
    save_output(
        [tmp_path / "report.json"],
        {"reviews": []},
        quiet=True,
        codebase_path=tmp_path,
    )
    runner = _build_runner(tmp_path)
    runner._has_grep = runner._has_find = True
    runner.timeout_seconds = 0.1
    database = tmp_path / ".metis" / "generated_artifacts.sqlite3"
    arguments = {
        "grep": ("needle", "."),
        "find_name": ("source.c",),
        "cat": ("source.c",),
    }
    busy_timeouts = []
    connect = sqlite3.connect

    def observe_connection(*args, **kwargs):
        reader = connect(*args, **kwargs)
        busy_timeouts.append(reader.execute("PRAGMA busy_timeout").fetchone()[0])
        return reader

    with closing(sqlite3.connect(database)) as connection:
        connection.execute("BEGIN EXCLUSIVE")
        monkeypatch.setattr(sqlite3, "connect", observe_connection)
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            getattr(runner, operation)(*arguments[operation])
        connection.rollback()

    assert busy_timeouts and all(
        0 < timeout <= runner.timeout_seconds * 1000 for timeout in busy_timeouts
    )
    assert runner.cat("source.c") == "1: needle source"


def test_python_search_timeout_kills_worker_and_allows_followup(tmp_path, monkeypatch):
    (tmp_path / "input.txt").write_text("needle\n", encoding="utf-8")
    runner = _build_runner(tmp_path)
    runner.timeout_seconds = 2
    processes = []
    popen = subprocess.Popen

    def record_process(argv, **kwargs):
        assert argv[0] == sys.executable
        if len(processes) == 1:
            argv = [sys.executable, "-c", "import time; time.sleep(10)"]
        process = popen(argv, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", record_process)
    assert runner.grep("needle", "input.txt")
    start = monotonic()

    with pytest.raises(subprocess.TimeoutExpired):
        runner.grep("needle", "input.txt")

    assert monotonic() - start < 4
    assert processes[-1].poll() is not None
    assert processes[-1].returncode != 0
    assert runner.grep("needle", "input.txt")


@pytest.mark.parametrize("pattern", ["needle", ";", r"\{\}", ""])
def test_relocated_state_keeps_native_search_and_exact_pruning(
    tmp_path, monkeypatch, pattern
):
    state = tmp_path / "storage" / "state[*]"
    state.mkdir(parents=True)
    (tmp_path / ".metis").symlink_to(state, target_is_directory=True)
    (state / "source.c").write_text("needle checkpoint\n", encoding="utf-8")
    source = tmp_path / "legitimate" / state.name
    source.mkdir(parents=True)
    (source / "source.c").write_text("needle source; {}\n", encoding="utf-8")
    runner = _build_runner(tmp_path)
    runner._has_grep = runner._has_find = True
    commands = []
    popen = subprocess.Popen

    def record_process(argv, **kwargs):
        commands.append(argv)
        return popen(argv, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", record_process)

    assert (
        runner.grep(pattern, ".")
        == "./legitimate/state[*]/source.c:1:needle source; {}"
    )
    assert runner.find_name("source.c") == ["legitimate/state[*]/source.c"]
    assert all(command[0] == "find" for command in commands)
    assert "grep" in commands[0]


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize(
    ("suffix", "directory"),
    [
        ("json", "("),
        ("sarif", "!"),
        ("html", "-reports"),
        ("csv", "reports"),
        ("json", "~"),
        ("json", "~metis-no-such-user"),
    ],
)
def test_generated_reports_are_excluded_across_navigation_restart(
    tmp_path, native, suffix, directory
):
    reports = tmp_path / directory
    reports.mkdir()
    source = reports / "source.c"
    source.write_text("needle source\n", encoding="utf-8")
    ignored = tmp_path / "ignored"
    ignored.mkdir()
    (tmp_path / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    (ignored / f"report.{suffix}").write_text(
        "needle ignored source\n", encoding="utf-8"
    )
    runner = _build_runner(tmp_path)
    runner._has_grep = runner._has_find = native
    original_matches = runner.grep("needle", str(reports))
    report = reports / f"report.{suffix}"
    save_output(
        [report],
        {
            "reviews": [
                {"file": "source.c", "reviews": [{"issue": "needle generated report"}]}
            ]
        },
        quiet=True,
        codebase_path=tmp_path,
    )
    alias = tmp_path / "report-alias"
    alias.symlink_to(report)
    runner = _build_runner(tmp_path)
    runner._has_grep = runner._has_find = native

    matches = runner.grep("needle", ".")

    assert "needle generated report" not in matches
    assert "needle source" in matches
    assert "needle ignored source" in matches
    targets = [str(reports)]
    if not directory.startswith("~"):
        targets.extend((reports.name, f"./{reports.name}"))
    for target in targets:
        assert runner.grep("needle", target) == original_matches
    assert runner.find_name(f"report.{suffix}") == [f"ignored/report.{suffix}"]
    for path in (report, alias):
        with pytest.raises(ValueError, match="Generated Metis artifacts"):
            runner.cat(str(path))
        with pytest.raises(ValueError, match="Generated Metis artifacts"):
            runner.sed(str(path), 1, 1)
        with pytest.raises(ValueError, match="Generated Metis artifacts"):
            runner.grep("needle", str(path))

    report.write_text("needle newly authored source\n", encoding="utf-8")

    assert "needle newly authored source" in runner.grep("needle", ".")
    assert runner.cat(str(report)) == "1: needle newly authored source"


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("root_alias", [False, True])
def test_generated_report_case_aliases_are_excluded(tmp_path, native, root_alias):
    root = tmp_path / "Repository"
    root.mkdir()
    reports = root / "Reports"
    reports.mkdir()
    alias = (tmp_path / "repository" if root_alias else root) / "reports"
    if not alias.exists():
        pytest.skip("Filesystem uses case-sensitive names")
    (reports / "source.c").write_text("needle source\n", encoding="utf-8")
    save_output(
        [alias / "report.json"],
        {"reviews": [{"file": "source.c", "reviews": [{"issue": "needle generated"}]}]},
        quiet=True,
        codebase_path=root,
    )
    runner = _build_runner(root)
    runner._has_grep = runner._has_find = native

    assert "needle generated" not in runner.grep("needle", ".")
    assert "needle source" in runner.grep("needle", "Reports")
    assert "needle generated" not in runner.grep("needle", str(alias))
    assert runner.cat(str(alias / "source.c")) == "1: needle source"
    assert runner.find_name("report.json") == []
    with pytest.raises(ValueError, match="Generated Metis artifacts"):
        runner.cat("Reports/report.json")
    with pytest.raises(ValueError, match="Generated Metis artifacts"):
        runner.sed("Reports/report.json", 1, 1)


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize(
    "name", [" source.c ", "source\n.c", "source\r.c", "source\r\n.c", "source[1].c"]
)
def test_find_name_preserves_complete_filename_records(tmp_path, native, name):
    directory = tmp_path / " source \\ directory "
    directory.mkdir()
    (directory / name).write_text("source\n", encoding="utf-8")
    (directory / "source1.c").write_text(
        "not the requested basename\n", encoding="utf-8"
    )
    runner = _build_runner(tmp_path)
    runner._has_find = native

    assert runner.find_name(name) == [
        (directory / name).relative_to(tmp_path).as_posix()
    ]

    runner.max_chars = 3
    assert runner.find_name(name) == []


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


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("state_name", [".metis", ".METIS", "relocated", "case_alias"])
def test_navigation_excludes_metis_state(tmp_path, native, state_name):
    state_paths = {"relocated": "storage/cache", "case_alias": "Storage/Cache"}
    state = tmp_path / state_paths.get(state_name, state_name)
    state.mkdir(parents=True)
    if state_name in {"relocated", "case_alias"}:
        target = state if state_name == "relocated" else tmp_path / "storage/cache"
        if not target.exists():
            pytest.skip("Filesystem uses case-sensitive names")
        state_name = ".metis"
        (tmp_path / state_name).symlink_to(target, target_is_directory=True)
    (state / "source.c").write_text("sentinel checkpoint\n" * 2000)
    (tmp_path / "state-alias").symlink_to(state, target_is_directory=True)
    (tmp_path / "report-alias.c").symlink_to(state / "source.c")
    ignored = tmp_path / "ignored" / "cache"
    ignored.mkdir(parents=True)
    (ignored / "source.c").write_text("sentinel source\n")
    (tmp_path / ".gitignore").write_text("ignored/\n")
    (tmp_path / ".metis.md").write_text("sentinel documentation\n")
    runner = _build_runner(tmp_path)
    runner._has_grep = runner._has_find = native

    matches = runner.grep("sentinel", ".")
    assert "sentinel source" in matches
    assert "sentinel documentation" in matches
    assert "sentinel checkpoint" not in matches
    assert runner.find_name("source.c") == ["ignored/cache/source.c"]
    assert runner.find_name(".metis.md") == [".metis.md"]

    for path in (f"{state_name}/source.c", "state-alias/source.c", "report-alias.c"):
        with pytest.raises(ValueError, match="Metis state is not source evidence"):
            runner.cat(path)
        with pytest.raises(ValueError, match="Metis state is not source evidence"):
            runner.sed(path, 1, 1)
        with pytest.raises(ValueError, match="Metis state is not source evidence"):
            runner.grep("sentinel", path)
