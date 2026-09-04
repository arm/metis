# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from contextlib import closing, nullcontext
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from metis.cli import commands
from metis.cli import review_checkpoints
from metis.cli.command_runtime import CommandRuntime
from metis.cli.review_checkpoints import review_checkpoint_callbacks
from metis.cli.review_progress import ExecutionGraphProgressReporter
from metis.cli.review_progress import ReviewCodeProgressReporter
from metis.engine.stages.review.models import ReviewCheckpointRecord
from metis.version import __version__ as METIS_VERSION


class _Progress:
    def __init__(self) -> None:
        self.messages: list[str] = []
        self.rules: list[str] = []
        self.removed: list[int] = []
        self.renderables = 0
        self.updates: list[dict[str, object]] = []
        self.console = SimpleNamespace(
            print=self.messages.append,
            rule=lambda title, **_kwargs: self.rules.append(title),
        )
        self._next_task = 0

    def add_task(self, description, **kwargs):
        self._next_task += 1
        self.updates.append(
            {"task": self._next_task, "description": description, **kwargs}
        )
        return self._next_task

    def remove_task(self, task):
        self.removed.append(task)

    def update(self, _task, **kwargs):
        self.updates.append({"task": _task, **kwargs})

    def get_renderable(self):
        self.renderables += 1
        return f"snapshot-{self.renderables}"


def test_review_progress_retains_rows_and_resume_position() -> None:
    progress = _Progress()
    reporter = ReviewCodeProgressReporter(progress)

    reporter({"event": "execution_stage_start", "stage": "review"})
    reporter({"event": "codegraph_reused"})
    reporter({"event": "review_files_start", "total": 10})
    reporter(
        {
            "event": "review_result",
            "node": "simple_llm_review",
            "completed": 4,
            "total": 10,
            "resumed": 4,
        }
    )

    assert progress.messages == ["[cyan]Stage: review[/cyan]"]
    assert any("CodeGraph reused" in str(update) for update in progress.updates)
    assert progress.updates[-1]["completed"] == 4
    assert "Resumed 4 files" in str(progress.updates[-1]["description"])


def test_parallel_review_progress_keeps_per_node_totals() -> None:
    progress = _Progress()
    reporter = ReviewCodeProgressReporter(progress)

    reporter(
        {
            "event": "review_files_start",
            "node": "simple_llm_review",
            "total": 100,
        }
    )
    reporter(
        {
            "event": "review_result",
            "node": "simple_llm_review",
            "completed": 10,
            "total": 100,
        }
    )
    reporter({"event": "review_files_start", "node": "reachability", "total": 20})
    reporter(
        {
            "event": "review_result",
            "node": "reachability",
            "completed": 1,
            "total": 20,
        }
    )
    reporter(
        {
            "event": "review_result",
            "node": "simple_llm_review",
            "completed": 11,
            "total": 100,
        }
    )

    simple_update = next(
        update for update in reversed(progress.updates) if update.get("task") == 2
    )
    reachability_update = next(
        update for update in reversed(progress.updates) if update.get("task") == 3
    )
    assert simple_update["total"] == 100
    assert simple_update["completed"] == 11
    assert reachability_update["total"] == 20
    assert reachability_update["completed"] == 1

    update_count = len(progress.updates)
    reporter(
        {
            "event": "configured_source_functions_done",
            "node": "codegraph",
        }
    )
    assert len(progress.updates) == update_count


@pytest.mark.parametrize(
    ("phase", "description"),
    (
        ("scope", "Preparing reachability scope"),
        ("analysis", "Building reachability analysis"),
        ("contracts", "Deriving reachability contracts"),
        ("evidence", "Preparing reachability evidence"),
        ("packets", "Reviewing reachability packets"),
    ),
)
def test_review_progress_names_reachability_phases(phase, description) -> None:
    progress = _Progress()
    reporter = ReviewCodeProgressReporter(progress)

    reporter(
        {
            "event": "reachability_phase_progress",
            "phase": phase,
            "completed": 2,
            "total": 8,
        }
    )

    assert description in str(progress.updates[-1]["description"])
    assert progress.updates[-1]["completed"] == 2


def test_review_progress_marks_inconclusive_nodes_yellow() -> None:
    progress = _Progress()
    reporter = ReviewCodeProgressReporter(progress)

    reporter(
        {
            "event": "execution_node_end",
            "node": "simple_llm_review",
            "status": "inconclusive",
        }
    )

    assert progress.updates[-1]["description"] == (
        "[yellow]! Simple LLM review complete[/yellow]"
    )


def test_verbose_direct_review_keeps_final_progress_rows(monkeypatch) -> None:
    transient_values: list[bool] = []
    progress = _Progress()

    def build_progress(*, transient: bool):
        transient_values.append(transient)
        return nullcontext(progress)

    engine = SimpleNamespace(execute_review=lambda *_args, **_kwargs: {"done": True})
    args = SimpleNamespace(output_file=None, quiet=False)
    monkeypatch.setattr(commands, "build_standard_progress", build_progress)

    assert commands._execute_review(
        engine,
        "code",
        None,
        args,
        "Reviewing...",
    ) == {"done": True}
    assert transient_values == [False]


def test_direct_review_honors_disabled_checkpoints(monkeypatch, tmp_path) -> None:
    captured: dict[str, object] = {}

    def execute_review(_mode, **kwargs):
        captured.update(kwargs["callbacks"])
        return {"done": True}

    engine = SimpleNamespace(
        codebase_path=str(tmp_path),
        execute_review=execute_review,
    )
    args = SimpleNamespace(
        output_file=[str(tmp_path / "review.json")],
        quiet=True,
        _review_checkpoints_enabled=False,
    )
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **func_kwargs: func(
            *func_args,
            **{key: value for key, value in func_kwargs.items() if key != "quiet"},
        ),
    )

    assert commands._execute_review(
        engine,
        "code",
        None,
        args,
        "Reviewing...",
    ) == {"done": True}
    assert "review_checkpoint_callback" not in captured
    assert "review_resume_callback" not in captured


def test_graph_progress_hands_review_rows_to_triage() -> None:
    progress = _Progress()
    reporter = ExecutionGraphProgressReporter(progress)

    def emit(kind: str, **payload: object) -> None:
        reporter({"event": kind, **payload})

    emit("execution_stage_start", stage="initialize")
    emit("execution_node_start", stage="initialize", node="threat_model")
    emit(
        "execution_node_end",
        stage="initialize",
        node="threat_model",
        status="ok",
    )
    emit("execution_stage_start", stage="review")
    emit("execution_node_end", stage="review", node="result", status="inconclusive")
    emit("execution_stage_start", stage="triage")
    emit("execution_node_start", stage="triage", node="triage")
    emit("start", total=2)
    emit("progress", completed=1, total=2)
    assert "Triaging findings 1/2" in str(progress.updates[-1]["description"])
    emit("progress", completed=2, total=2)
    emit("done", total=2, decision={"status": "valid"})
    emit("done", total=2, decision={"status": "invalid"})
    emit("execution_node_end", stage="triage", node="triage", status="ok")
    emit("execution_node_end", stage="triage", node="result", status="inconclusive")
    reporter.finish()

    assert progress.rules == ["Init", "Review", "Triage"]
    assert progress.removed == [1, 2, 3, 4]
    assert progress.renderables == 2
    assert "[green]✓ review.result complete[/green]" in progress.messages
    assert "[green]✓ triage.result complete[/green]" in progress.messages
    assert any(
        "[green]Valid: 1[/green] [red]Invalid: 1[/red]"
        in str(update.get("description"))
        for update in progress.updates
    )


@pytest.mark.parametrize(
    ("command", "mode", "filename"),
    [
        ("review_code", "code", None),
        ("review_patch", "patch", "change.diff"),
        ("review_file", "file", "a.c"),
    ],
)
def test_review_commands_route_through_graph(
    monkeypatch,
    tmp_path,
    command,
    mode,
    filename,
):
    calls = []

    class _Engine:
        def execute_review(self, mode, **kwargs):
            calls.append((mode, kwargs))
            return {
                "formats": ("sarif", "json", "html", "csv"),
                "findings": {"reviews": []},
                "sarif": {"version": "2.1.0", "runs": []},
            }

    args = SimpleNamespace(
        verbose=True,
        quiet=True,
        triage=False,
        output_file=[str(tmp_path / "report.json")],
    )
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **func_kwargs: func(
            *func_args,
            **{k: v for k, v in func_kwargs.items() if k != "quiet"},
        ),
    )
    monkeypatch.setattr(
        commands, "_finalize_review_output", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)

    target = None
    if filename is not None:
        target_path = tmp_path / filename
        target_path.write_text("review input", encoding="utf-8")
        target = str(target_path)
    runtime = CommandRuntime(command=command, command_args=[target] if target else [])

    if command == "review_code":
        commands.run_review_code(_Engine(), args, runtime)
    elif command == "review_patch":
        commands.run_review(_Engine(), target, args, runtime)
    else:
        commands.run_file_review(_Engine(), target, args, runtime)

    assert calls[0][0] == mode
    assert calls[0][1]["target"] == target
    assert callable(calls[0][1]["callbacks"]["diagnostic_callback"])
    assert callable(calls[0][1]["callbacks"]["review_checkpoint_callback"])
    assert callable(calls[0][1]["callbacks"]["review_resume_callback"])
    assert {path.rsplit(".", 1)[-1] for path in args.output_file} == {
        "sarif",
        "json",
        "html",
        "csv",
    }


def test_review_producers_keep_separate_resumable_outputs(tmp_path):
    callbacks = review_checkpoint_callbacks(
        codebase_path=tmp_path,
        enabled=True,
    )
    checkpoint = callbacks["review_checkpoint_callback"]
    resume = callbacks["review_resume_callback"]

    simple = ReviewCheckpointRecord(
        metis_version=METIS_VERSION,
        producer="simple_llm_review",
        key="file:key",
        record={"reviews": []},
    )
    reachability = ReviewCheckpointRecord(
        metis_version=METIS_VERSION,
        producer="reachability",
        key="packet:key",
        record={"reviews": []},
    )
    checkpoint(simple.model_dump(mode="json"), 1, 1)
    checkpoint(reachability.model_dump(mode="json"), 1, 1)
    checkpoint(
        simple.model_copy(
            update={"key": "file:next", "record": {"reviews": [{"issue": "next"}]}}
        ).model_dump(mode="json"),
        2,
        2,
    )

    checkpoint_dir = tmp_path / ".metis" / "checkpoints"
    assert (checkpoint_dir / "review.simple_llm_review.sqlite3").exists()
    assert (checkpoint_dir / "review.reachability.sqlite3").exists()
    assert resume("simple_llm_review") == {
        "file:key": simple.record,
        "file:next": {"reviews": [{"issue": "next"}]},
    }
    assert resume("reachability") == {"packet:key": reachability.record}
    other_output = review_checkpoint_callbacks(
        codebase_path=tmp_path,
        enabled=True,
    )
    assert other_output["review_resume_callback"]("simple_llm_review") == {
        "file:key": simple.record,
        "file:next": {"reviews": [{"issue": "next"}]},
    }


def test_review_checkpoint_reader_preserves_locked_database(monkeypatch, tmp_path):
    callbacks = review_checkpoint_callbacks(codebase_path=tmp_path, enabled=True)
    record = ReviewCheckpointRecord(
        metis_version=METIS_VERSION,
        producer="simple_llm_review",
        key="file:key",
        record={"reviews": []},
    )
    callbacks["review_checkpoint_callback"](record.model_dump(mode="json"), 1, 1)
    checkpoint_path = (
        tmp_path / ".metis" / "checkpoints" / "review.simple_llm_review.sqlite3"
    )
    connect = review_checkpoints._connect_checkpoint

    def connect_without_wait(path):
        connection = connect(path)
        connection.execute("PRAGMA busy_timeout = 0")
        return connection

    monkeypatch.setattr(review_checkpoints, "_connect_checkpoint", connect_without_wait)
    with closing(sqlite3.connect(checkpoint_path)) as blocker:
        blocker.execute("BEGIN EXCLUSIVE")
        assert callbacks["review_resume_callback"]("simple_llm_review") is None

    assert callbacks["review_resume_callback"]("simple_llm_review") == {
        "file:key": record.record
    }


def test_review_checkpoints_can_be_disabled(tmp_path):
    callbacks = review_checkpoint_callbacks(
        codebase_path=tmp_path,
        enabled=False,
    )

    assert callbacks == {}
    assert not (tmp_path / ".metis").exists()


def test_review_checkpoints_replace_incompatible_database(tmp_path):
    checkpoint_path = (
        tmp_path / ".metis" / "checkpoints" / "review.simple_llm_review.sqlite3"
    )
    checkpoint_path.parent.mkdir(parents=True)
    with sqlite3.connect(checkpoint_path) as connection:
        connection.execute(
            """
            CREATE TABLE review_checkpoint_records (
                producer TEXT NOT NULL,
                metis_version TEXT NOT NULL,
                record_key TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (producer, metis_version, record_key)
            ) WITHOUT ROWID
            """
        )

    callbacks = review_checkpoint_callbacks(codebase_path=tmp_path, enabled=True)
    record = ReviewCheckpointRecord(
        metis_version=METIS_VERSION,
        producer="simple_llm_review",
        key="file:key",
        record={"reviews": []},
    )
    callbacks["review_checkpoint_callback"](
        record.model_dump(mode="json"),
        1,
        1,
    )

    assert callbacks["review_resume_callback"]("simple_llm_review") == {
        "file:key": record.record
    }


def test_run_update_uses_indexing_domain_surface(monkeypatch, tmp_path):
    patch_file = tmp_path / "change.diff"
    patch_file.write_text("diff --git a/a.py b/a.py", encoding="utf-8")

    captured: list[str] = []

    class _IndexingDomain:
        def update_index(self, patch_text):
            captured.append(patch_text)

    engine = SimpleNamespace(indexing=_IndexingDomain())
    args = SimpleNamespace(quiet=True)

    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **_func_kwargs: func(*func_args),
    )

    commands.run_update(
        engine,
        str(patch_file),
        args,
        CommandRuntime(
            command="update",
            command_args=[str(patch_file)],
        ),
    )

    assert captured == ["diff --git a/a.py b/a.py"]


def test_run_index_verbose_uses_indexing_domain_surface(monkeypatch):
    calls: list[str] = []

    class _IndexingDomain:
        def count_index_items(self):
            calls.append("count")
            return 2

        def index_prepare_nodes_iter(self):
            calls.append("prepare")
            yield None
            yield None

        def index_finalize_embeddings(self):
            calls.append("finalize")

    engine = SimpleNamespace(indexing=_IndexingDomain())

    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands, "iterate_with_progress", lambda _total, iterable: list(iterable)
    )
    monkeypatch.setattr(
        commands, "with_timer", lambda _message, func, **_kwargs: func()
    )

    commands.run_index(engine, verbose=True, quiet=True)

    assert calls == ["count", "prepare", "finalize"]


def test_run_review_code_triggers_triage_when_global_flag_enabled(monkeypatch):
    calls = []
    codegraph = object()

    class _Engine:
        def execute_review(self, mode, **kwargs):
            calls.append((mode, kwargs))
            return {
                "formats": ("sarif", "json", "html", "csv"),
                "findings": {"reviews": []},
                "sarif": {"version": "2.1.0", "runs": []},
                "codegraph": codegraph,
            }

        def execute_triage(self, payload, **kwargs):
            calls.append(
                (
                    "triage",
                    kwargs["options"],
                    kwargs["codegraph"],
                )
            )
            return {"formats": ("sarif",), "sarif": payload}

    engine = _Engine()
    args = SimpleNamespace(
        verbose=False,
        quiet=True,
        triage=True,
        include_triaged=False,
        output_file=None,
    )
    runtime = CommandRuntime(
        command="review_code",
        command_args=[],
    )

    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **func_kwargs: func(
            *func_args,
            **{k: v for k, v in func_kwargs.items() if k != "quiet"},
        ),
    )
    monkeypatch.setattr(
        commands, "pretty_print_reviews", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(commands, "save_output", lambda *_args, **_kwargs: None)

    commands.run_review_code(engine, args, runtime)

    assert calls[0][0] == "code"
    assert calls[0][1]["target"] is None
    assert callable(calls[0][1]["callbacks"]["diagnostic_callback"])
    assert calls[1] == ("triage", None, codegraph)


def test_review_command_honors_explicit_format_in_addition_to_graph_formats(
    monkeypatch,
):
    class _Engine:
        def execute_review(self, _mode, **_kwargs):
            return {
                "formats": ("sarif",),
                "findings": {"reviews": []},
                "sarif": {"version": "2.1.0", "runs": []},
            }

    args = SimpleNamespace(
        quiet=True,
        triage=False,
        output_file=["report.json"],
    )
    saved: list[str] = []

    def capture_output(_results, final_args, **_kwargs):
        saved.extend(final_args.output_file)

    monkeypatch.setattr(commands, "_finalize_review_output", capture_output)

    commands.run_review_code(
        _Engine(),
        args,
        CommandRuntime(command="review_code", command_args=[]),
    )

    assert {Path(path).suffix for path in saved} == {".json", ".sarif"}


def test_run_review_code_preserves_review_output_when_triage_fails(monkeypatch):
    saved = []

    class _Engine:
        def execute_review(self, _mode, **_kwargs):
            return {
                "formats": ("sarif", "json", "html", "csv"),
                "findings": {"reviews": []},
                "sarif": {"version": "2.1.0", "runs": [{"results": []}]},
            }

        def execute_triage(self, _payload, **_kwargs):
            raise RuntimeError("provider unavailable")

    args = SimpleNamespace(
        verbose=False,
        quiet=True,
        triage=True,
        include_triaged=False,
        output_file=None,
    )
    runtime = CommandRuntime(command="review_code", command_args=[])
    monkeypatch.setattr(
        commands,
        "with_spinner",
        lambda _message, func, *func_args, **func_kwargs: func(
            *func_args,
            **{k: v for k, v in func_kwargs.items() if k != "quiet"},
        ),
    )
    monkeypatch.setattr(commands, "print_console", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(commands, "pretty_print_reviews", lambda *_args: None)
    monkeypatch.setattr(
        commands,
        "save_output",
        lambda *_args, **kwargs: saved.append(kwargs["sarif_payload"]),
    )

    commands.run_review_code(_Engine(), args, runtime)

    assert saved == [{"version": "2.1.0", "runs": [{"results": []}]}]
